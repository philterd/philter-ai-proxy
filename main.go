package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
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
	vertexTarget            *url.URL    // nil when Vertex is not configured
	vertexClient            *http.Client
	vertexTokenSource       tokenSource // non-nil when Vertex is configured
	openaiCompatibleTargets map[string]*url.URL
	openaiCompatibleClients map[string]*http.Client
	philter                 *PhilterClient
	auditLogger             *slog.Logger
	metrics                 *ProxyMetrics
	keyStore                *keyStore // hashed API keys; nil when auth is disabled
	concurrency             *ConcurrencyLimiter
	// trustedProxies are pre-parsed CIDRs corresponding to
	// cfg.Listen.TrustedProxies. Used by clientIP() to decide whether to
	// honor the X-Forwarded-For header from a given peer. Empty = never
	// trust XFF.
	trustedProxies []*net.IPNet
}

type AuditEntry struct {
	RequestID      string        `json:"request_id"`
	Direction      string        `json:"direction"`
	Provider       string        `json:"provider"`
	Model          string        `json:"model"`
	PolicyName     string        `json:"policy_name"`
	DocumentID     string        `json:"document_id"`
	FieldsRedacted int           `json:"fields_redacted"`
	EntityCount    int           `json:"entity_count"`
	EntityTypes    []string      `json:"entity_types"`
	RedactLatency  time.Duration `json:"redact_latency_ms"`
	ClientIP       string        `json:"client_ip"`
	// KeyID is the opaque stable identifier (`key-N`) of the authenticated
	// API key, or empty when no key was authenticated. Never the raw key.
	KeyID            string `json:"key_id,omitempty"`
	HTTPStatus       int    `json:"http_status"`
	PromptTokens     int    `json:"prompt_tokens,omitempty"`
	CompletionTokens int    `json:"completion_tokens,omitempty"`
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

// shouldForwardHeader reports whether a header from the inbound request
// should be copied onto the outbound provider request. Returns false for
// hop-by-hop headers and for any X-Philter-* header (the proxy's auth key
// and policy hints are both in this namespace; neither should
// reach the LLM provider). Header keys from http.Header iteration are
// already canonical-cased, so a prefix match against "X-Philter-" is
// sufficient.
func shouldForwardHeader(key string) bool {
	if hopByHopHeaders[key] {
		return false
	}
	if strings.HasPrefix(key, "X-Philter-") {
		return false
	}
	return true
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
// writeBadJSON emits a generic "invalid request body" client response while
// logging the underlying parse error server-side. Echoing json.Unmarshal's
// "invalid character ... at offset N" message to the client is harmless in
// most cases but tells a probing attacker the structural sensitivity of the
// parser and helps fingerprint version differences. The audit log carries
// the request_id so an operator can trace the failure back to this server
// log line.
func (p *Proxy) writeBadJSON(w http.ResponseWriter, audit *AuditEntry, err error) {
	slog.Warn("Invalid JSON request body", "error", err, "request_id", auditRequestID(audit))
	writeError(w, audit, http.StatusBadRequest, "invalid_request", "bad_json", "invalid JSON in request body")
}

// writeMarshalFailed emits a generic 500 while logging the marshal error
// server-side. Reaching this path means an internal data structure failed
// to re-serialize after redaction; the raw error references field names
// and struct shapes that are implementation details.
func (p *Proxy) writeMarshalFailed(w http.ResponseWriter, audit *AuditEntry, err error) {
	slog.Error("Failed to marshal redacted request", "error", err, "request_id", auditRequestID(audit))
	writeError(w, audit, http.StatusInternalServerError, "internal_error", "marshal_failed", "failed to re-serialize redacted request")
}

// writeBodyReadError emits a generic 400 for client-body read failures while
// logging the underlying error server-side.
func (p *Proxy) writeBodyReadError(w http.ResponseWriter, audit *AuditEntry, err error) {
	slog.Warn("Failed to read request body", "error", err, "request_id", auditRequestID(audit))
	writeError(w, audit, http.StatusBadRequest, "invalid_request", "body_read", "failed to read request body")
}

// auditRequestID returns the request_id from the audit entry, or empty if
// the entry is nil. Used by the error helpers above for server-side logs.
func auditRequestID(a *AuditEntry) string {
	if a == nil {
		return ""
	}
	return a.RequestID
}

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

// isCanonicalPath reports whether `p` is already in canonical form: it
// equals `path.Clean(p)`. The check rejects any path containing `.` /
// `..` segments, redundant slashes, or trailing slashes (other than the
// root `/`). This is deliberately strict: real LLM API clients construct
// canonical paths, and refusing the alternatives forecloses every flavor
// of path-traversal-based scope bypass without the proxy needing to
// re-canonicalize at every path-sensitive site.
//
// Edge case: path.Clean("") returns ".". The check still rejects "".
func isCanonicalPath(p string) bool {
	if p == "" {
		return false
	}
	return path.Clean(p) == p
}

// maxInboundRequestIDLen is the upper bound on the length of a client-
// supplied X-Request-Id the proxy will adopt. Anything longer is replaced
// with a freshly-generated UUID. 128 bytes is comfortably larger than any
// standard identifier (UUID is 36 chars, ULID 26, W3C trace-id 32 hex chars
// + 16 hex chars span) while bounding memory amplification.
const maxInboundRequestIDLen = 128

// sanitizeInboundRequestID returns the client-supplied request ID when it
// is within length bounds and contains only printable ASCII, otherwise
// returns empty (signaling the caller should mint a fresh UUID). The
// constraints serve two purposes:
//
//  1. Memory amplification cap. The request_id is propagated into the
//     audit-log entry and possibly other operator-visible logs; without a
//     length bound, a 10MB header value would balloon every log line.
//  2. Log-injection / structured-log poisoning. Control characters (CR/LF
//     in particular) and non-ASCII bytes can break log parsers downstream.
//     Restricting to printable ASCII removes the surface.
func sanitizeInboundRequestID(id string) string {
	if id == "" || len(id) > maxInboundRequestIDLen {
		return ""
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c < 0x20 || c > 0x7E {
			return ""
		}
	}
	return id
}

// safeQueryParams is the allow-list of query parameters whose values may
// appear verbatim in operator-facing logs (slog warnings, error log lines,
// etc.). Every other parameter is replaced with "REDACTED" before logging
// because the proxy cannot statically know which knobs a given provider
// (or a future one) treats as a credential. Erring toward redaction is
// strictly safer than maintaining an ever-growing list of sensitive
// parameter names. The allow-list covers the few well-known routing /
// versioning knobs LLM providers use today; add to it only after
// confirming the value is never sensitive across all supported providers.
var safeQueryParams = map[string]bool{
	"api-version": true, // Azure OpenAI routing
	"alt":         true, // Vertex AI: alt=sse for streaming
	"prettyPrint": true, // Google APIs convention
	"prettyprint": true,
}

// sanitizeQuery redacts every query parameter that is not in
// safeQueryParams. Used for log lines that include a request URL (e.g. the
// upstream-failure warning) so credentials accidentally placed in the query
// string by a misbehaving client never reach disk.
func sanitizeQuery(rawQuery string) string {
	params, err := url.ParseQuery(rawQuery)
	if err != nil {
		// Unparseable: the safest action is to drop the whole query rather
		// than echo a possibly-malformed credential string back into the log.
		return "REDACTED"
	}
	for name, vals := range params {
		if safeQueryParams[name] {
			continue
		}
		for i := range vals {
			vals[i] = "REDACTED"
		}
		params[name] = vals
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
	case "gemini", "vertex":
		// Vertex returns the same Gemini schema (usageMetadata with
		// promptTokenCount / candidatesTokenCount).
		meta, _ := raw["usageMetadata"].(map[string]interface{})
		return fi(meta, "promptTokenCount"), fi(meta, "candidatesTokenCount")
	case "ollama":
		return fi(raw, "prompt_eval_count"), fi(raw, "eval_count")
	case "bedrock":
		usage, _ := raw["usage"].(map[string]interface{})
		return fi(usage, "inputTokens"), fi(usage, "outputTokens")
	default: // openai, openai-compatible, azure
		usage, _ := raw["usage"].(map[string]interface{})
		// Chat/embeddings report prompt_tokens/completion_tokens; the Responses
		// API reports input_tokens/output_tokens. Fall back so all OpenAI-style
		// endpoints are accounted for. (Embeddings omit completion entirely.)
		prompt := fi(usage, "prompt_tokens")
		if prompt == 0 {
			prompt = fi(usage, "input_tokens")
		}
		completion := fi(usage, "completion_tokens")
		if completion == 0 {
			completion = fi(usage, "output_tokens")
		}
		return prompt, completion
	}
}

// jsonInt returns m[key] as an int when present and numeric, else 0.
func jsonInt(m map[string]interface{}, key string) int {
	if m == nil {
		return 0
	}
	v, _ := m[key].(float64)
	return int(v)
}

// streamingUsageSupported reports whether streamed token-usage extraction is
// implemented for a provider. Only OpenAI-family and Anthropic streams carry a
// usage event in a shape we parse; the others (Gemini/Vertex/Ollama/Bedrock)
// are not extracted from streams, so the scanner stays a no-op for them.
func streamingUsageSupported(provider string) bool {
	switch provider {
	case "gemini", "vertex", "ollama", "bedrock":
		return false
	default: // openai, azure, openai-compatible custom names, anthropic
		return true
	}
}

// extractStreamingUsage pulls token usage from a single streamed SSE/NDJSON
// event's JSON object. Streaming usage shapes differ from the non-streaming
// body: OpenAI emits a final chunk carrying a top-level `usage` object (when the
// client sets stream_options.include_usage); Anthropic splits usage across
// `message_start` (input_tokens nested under message.usage) and `message_delta`
// (output_tokens in a top-level usage). Returns (0, 0) for events without usage.
func extractStreamingUsage(provider string, eventJSON []byte) (prompt, completion int) {
	var raw map[string]interface{}
	if err := json.Unmarshal(eventJSON, &raw); err != nil {
		return 0, 0
	}
	switch provider {
	case "anthropic":
		// message_start nests usage under message.usage; message_delta carries
		// a top-level usage. Read whichever this event has.
		if msg, ok := raw["message"].(map[string]interface{}); ok {
			if u, ok := msg["usage"].(map[string]interface{}); ok {
				return jsonInt(u, "input_tokens"), jsonInt(u, "output_tokens")
			}
		}
		if u, ok := raw["usage"].(map[string]interface{}); ok {
			return jsonInt(u, "input_tokens"), jsonInt(u, "output_tokens")
		}
		return 0, 0
	default: // openai, azure, openai-compatible
		u, _ := raw["usage"].(map[string]interface{})
		prompt = jsonInt(u, "prompt_tokens")
		if prompt == 0 {
			prompt = jsonInt(u, "input_tokens")
		}
		completion = jsonInt(u, "completion_tokens")
		if completion == 0 {
			completion = jsonInt(u, "output_tokens")
		}
		return prompt, completion
	}
}

// streamUsageScanner extracts token usage from a streamed response without
// buffering the whole stream: it retains only the current partial line and
// parses each complete SSE/NDJSON line as it arrives, keeping the last non-zero
// usage seen for each field. Last-wins is correct for both supported providers
// (OpenAI reports usage once in the final chunk; Anthropic sets input_tokens in
// message_start and updates output_tokens across message_delta events).
type streamUsageScanner struct {
	provider   string
	enabled    bool
	partial    []byte
	prompt     int
	completion int
}

func newStreamUsageScanner(provider string) *streamUsageScanner {
	return &streamUsageScanner{provider: provider, enabled: streamingUsageSupported(provider)}
}

// write feeds a chunk of streamed bytes to the scanner, parsing any newly
// completed lines. It is a no-op for providers without streaming-usage support.
func (s *streamUsageScanner) write(p []byte) {
	if !s.enabled {
		return
	}
	s.partial = append(s.partial, p...)
	for {
		i := bytes.IndexByte(s.partial, '\n')
		if i < 0 {
			break
		}
		line := s.partial[:i]
		s.partial = s.partial[i+1:]
		s.scanLine(line)
	}
}

// close flushes any trailing line not terminated by a newline (e.g. a provider
// that omits the final newline). Malformed remnants are ignored by the parser.
func (s *streamUsageScanner) close() {
	if !s.enabled {
		return
	}
	s.scanLine(s.partial)
	s.partial = nil
}

func (s *streamUsageScanner) scanLine(line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	// SSE data lines are "data: {json}"; NDJSON lines are a bare "{json}".
	if rest, ok := bytes.CutPrefix(line, []byte("data:")); ok {
		line = bytes.TrimSpace(rest)
	}
	if len(line) == 0 || line[0] != '{' {
		return // "[DONE]", "event: ...", id/retry/comment lines
	}
	if prompt, completion := extractStreamingUsage(s.provider, line); prompt > 0 || completion > 0 {
		if prompt > 0 {
			s.prompt = prompt
		}
		if completion > 0 {
			s.completion = completion
		}
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
		if !shouldForwardHeader(key) {
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
	// Tee streamed bytes through a usage scanner so token accounting works for
	// streaming responses too. Chunks are still written and flushed immediately,
	// so this does not buffer or delay the stream.
	usage := newStreamUsageScanner(provider)
	streamCopy(w, resp.Body, usage.write)
	usage.close()
	if audit != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if usage.prompt > 0 {
			audit.PromptTokens = usage.prompt
		}
		if usage.completion > 0 {
			audit.CompletionTokens = usage.completion
		}
	}
}

// streamCopy forwards a response body to the client chunk by chunk, flushing
// after each write so streamed responses are delivered in real time rather than
// buffered. When tee is non-nil, each chunk is also handed to it (e.g. a
// token-usage scanner) before the next read reuses the buffer.
func streamCopy(w http.ResponseWriter, body io.Reader, tee func([]byte)) {
	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 4096)
	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if tee != nil {
				tee(buf[:n])
			}
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
		"key_id", entry.KeyID,
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
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
		// Pin TLS 1.2 as the minimum. Go 1.25 already defaults to TLS 1.2,
		// but compliance audits routinely flag implicit defaults; making
		// this explicit closes that finding and survives any future
		// stdlib default change.
		MinVersion: tls.VersionTLS12,
	}

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

// noFollowRedirects is the CheckRedirect policy applied to every outbound
// http.Client the proxy constructs. LLM APIs do not use redirects, so the
// only callers a 3xx benefits are a compromised upstream or a DNS-hijacked
// host attempting to siphon credentials. Returning ErrUseLastResponse tells
// net/http to surface the 3xx response unchanged, never re-sending the
// request (with its Authorization / api-key / signed-SigV4 headers) to the
// redirect target.
func noFollowRedirects(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// disableRedirects sets the no-follow policy on `c` and returns it. Used to
// keep the construction call sites compact (`disableRedirects(&http.Client{...})`).
func disableRedirects(c *http.Client) *http.Client {
	c.CheckRedirect = noFollowRedirects
	return c
}

// parseTrustedProxies converts the operator-supplied CIDR strings into
// *net.IPNet values for clientIP() to consult on every request. Invalid
// entries are rejected at validateConfig before we reach this point; the
// double-check here returns nil for any unparseable entry so a startup typo
// (caught upstream) cannot cause a runtime panic.
func parseTrustedProxies(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil || ipnet == nil {
			continue
		}
		out = append(out, ipnet)
	}
	return out
}

// clientIP returns the apparent client IP for `r`. The X-Forwarded-For header
// is consulted ONLY when the immediate TCP peer (`r.RemoteAddr`) is inside one
// of the configured trustedProxies CIDRs; otherwise the header is ignored to
// prevent untrusted clients from spoofing their source IP and corrupting
// audit-log correlation. The empty-trustedProxies default is
// therefore "never trust XFF", which is the safe behavior when the proxy is
// exposed directly to the internet.
func (p *Proxy) clientIP(r *http.Request) string {
	peer := remoteHost(r.RemoteAddr)
	if peerTrusted(peer, p.trustedProxies) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// Honor the left-most entry, which is the original client IP per
			// the X-Forwarded-For convention. Trim whitespace because some
			// proxies emit ", "-separated lists.
			first := strings.SplitN(fwd, ",", 2)[0]
			return strings.TrimSpace(first)
		}
	}
	return peer
}

// remoteHost extracts the IP portion of a `host:port` address. Supports IPv4
// and IPv6 (the bracketed form `[::1]:8080`).
func remoteHost(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

// peerTrusted reports whether the connecting peer IP falls inside any of the
// configured trusted-proxy CIDRs.
func peerTrusted(peer string, trusted []*net.IPNet) bool {
	if len(trusted) == 0 || peer == "" {
		return false
	}
	ip := net.ParseIP(peer)
	if ip == nil {
		return false
	}
	for _, cidr := range trusted {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
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

// blocksUnscannableStreams reports whether a streaming response must be
// rejected rather than forwarded unscanned. Only `block` promises the client
// sees no undetected PII, so only `block` fails closed.
func blocksUnscannableStreams(outbound OutboundConfig) bool {
	return outbound.Action == "block" && !outbound.AllowUnscannedStreams
}

// rejectUnscannableStream refuses a streaming response on a route configured to
// block. A client can select streaming itself with `"stream": true`, so passing
// it through would be a client-triggerable bypass. Both callers buffer the
// response first, so nothing has reached the client yet.
func (p *Proxy) rejectUnscannableStream(w http.ResponseWriter, audit, outboundAudit *AuditEntry, provider, docID string) {
	slog.Warn("Blocked unscannable streaming response",
		"provider", provider, "document_id", docID, "outbound_action", "block")
	outboundAudit.HTTPStatus = http.StatusForbidden
	outboundAudit.ErrorType, outboundAudit.ErrorCode = "pii_blocked", "outbound_stream_unscannable"
	emitAuditLog(p.auditLogger, *outboundAudit)
	writeError(w, audit, http.StatusForbidden, "pii_blocked", "outbound_stream_unscannable",
		"response blocked: streaming responses cannot be scanned for PII")
}

func isStreamingResponse(headers http.Header) bool {
	ct := headers.Get("Content-Type")
	return strings.Contains(ct, "text/event-stream") ||
		strings.Contains(ct, "application/x-ndjson") ||
		// Bedrock ConverseStream returns the AWS binary event-stream framing.
		strings.Contains(ct, "application/vnd.amazon.eventstream")
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
		if !shouldForwardHeader(key) {
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
	philterCtx, docID, policy string, outbound OutboundConfig,
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

	streaming := isStreamingResponse(respHeaders)
	success := statusCode >= 200 && statusCode < 300

	if success && !streaming {
		modified, blocked, scanErr := scanner(r.Context(), respBody, philterCtx, docID, policy, outbound.Action, outboundAudit)
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
	} else if streaming {
		if success && blocksUnscannableStreams(outbound) {
			p.rejectUnscannableStream(w, audit, outboundAudit, provider, docID)
			return
		}
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
	return len(parts) == 3 && parts[0] == "model" &&
		(parts[2] == "converse" || parts[2] == "converse-stream")
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
	return disableRedirects(&http.Client{
		Transport: newProviderTransport(&tls.Config{
			InsecureSkipVerify: skipVerify,
			MinVersion:         tls.VersionTLS12,
		}, t),
	})
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
		p.writeBadJSON(w, audit, err)
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
		p.writeMarshalFailed(w, audit, err)
		return
	}

	if outbound.Enabled {
		p.forwardBedrockWithOutboundScan(w, r, body, philterCtx, docID, policyName, outbound, audit)
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

	for key, values := range resp.Header {
		if hopByHopHeaders[key] {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	// ConverseStream (/model/{id}/converse-stream) returns the AWS binary
	// event-stream framing; pass those frames through to the client without
	// buffering. Token usage is carried in a terminal binary `metadata` frame we
	// do not parse, so streamed Bedrock usage is not accounted (matching the
	// other providers, where streamed usage is only extracted for OpenAI/Anthropic).
	if isStreamingResponse(resp.Header) {
		w.WriteHeader(resp.StatusCode)
		streamCopy(w, resp.Body, nil)
		return
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
	philterCtx, docID, policy string, outbound OutboundConfig,
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

	streaming := isStreamingResponse(respHeaders)
	success := statusCode >= 200 && statusCode < 300

	if success && !streaming {
		modified, blocked, scanErr := p.scanBedrockResponse(r.Context(), respBody, philterCtx, docID, policy, outbound.Action, outboundAudit)
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
	} else if streaming {
		if success && blocksUnscannableStreams(outbound) {
			p.rejectUnscannableStream(w, audit, outboundAudit, "bedrock", docID)
			return
		}
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
	}

	// Establish the request_id up front so every downstream error path can
	// reference it. An inbound X-Request-Id is honored for tracing across
	// hops, but only when it looks like a sane identifier: capped at 128
	// printable ASCII characters and free of control bytes. Otherwise we
	// generate a fresh UUID. This bounds memory amplification (a client
	// cannot ship a multi-megabyte X-Request-Id that gets retained in audit
	// logs) and rules out log-injection vectors via control characters.
	requestID := sanitizeInboundRequestID(r.Header.Get("X-Request-Id"))
	if requestID == "" {
		requestID = uuid.New().String()
	}
	w.Header().Set("X-Request-Id", requestID)

	// Build the audit entry early so even auth / concurrency
	// rejections produce a log line. Fields that aren't known yet stay empty;
	// later code fills them in as the request progresses.
	//
	// TraceID is read from the request context, which carries the root span
	// installed by otelhttp when tracing is active (empty otherwise). This
	// links audit log lines to APM traces by W3C trace ID.
	audit := &AuditEntry{
		RequestID: requestID,
		Direction: "inbound",
		ClientIP:  p.clientIP(r),
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
			if audit.PromptTokens > 0 || audit.CompletionTokens > 0 {
				// modelLabel is reduced through the per-provider
				// cardinality cap so a client cannot drive Prometheus
				// OOM by emitting one request per random model string.
				modelLabel := p.metrics.modelLabels.reduce(audit.Provider, audit.Model)
				if audit.PromptTokens > 0 {
					p.metrics.promptTokensTotal.WithLabelValues(audit.Provider, modelLabel).Add(float64(audit.PromptTokens))
				}
				if audit.CompletionTokens > 0 {
					p.metrics.completionTokensTotal.WithLabelValues(audit.Provider, modelLabel).Add(float64(audit.CompletionTokens))
				}
			}
		}
	}()

	// Path canonicalization gate. We reject any request whose path is not
	// already in canonical form (i.e. path.Clean(p) != p). This closes a
	// scope-bypass class: a key restricted to `/v1/chat/` via per-key
	// scopes would otherwise accept `/v1/chat/../v1/embeddings/x` (the
	// HasPrefix scope check passes) and forward the un-normalized path to
	// an upstream that normalizes it before routing -- effectively
	// reaching `/v1/embeddings/x`. Refusing non-canonical paths up front
	// is simpler and safer than re-normalizing every path-matching site.
	if !isCanonicalPath(r.URL.Path) {
		writeError(rc, audit, http.StatusBadRequest, "invalid_request", "path_not_canonical", "request path is not in canonical form")
		return
	}

	// API key authentication. Enforced only when keys are configured; disabled by default.
	// clientKeyID is the stable per-entry identifier recorded in the audit
	// log and operator log lines; never the raw key.
	var clientKeyID string
	var keyBoundPolicy string
	var keyScopes *APIKeyScopes
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
		resolved, ok := p.keyStore.lookup(clientKey)
		if !ok {
			writeError(rc, audit, http.StatusUnauthorized, "unauthorized", "invalid_api_key", "invalid API key")
			return
		}
		clientKeyID = resolved.ID
		keyBoundPolicy = resolved.Policy
		keyScopes = resolved.Scopes
		audit.KeyID = clientKeyID
		// Strip the proxy auth header so it is never forwarded to the LLM provider.
		r.Header.Del(headerName)
	}

	// Concurrency guard. Bounds the number of in-flight requests with a graceful
	// 503 + Retry-After when the configured ceiling is reached. Acquire happens
	// after auth so junk traffic is rejected before it can occupy a slot.
	if p.concurrency != nil {
		allowed, scope, release := p.concurrency.Acquire()
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

	// Cap the inbound request body. MaxBytesReader makes ReadAll fail with
	// *http.MaxBytesError once the limit is exceeded (and signals the server to
	// close the connection). The original w is passed so that signal works.
	r.Body = http.MaxBytesReader(w, r.Body, p.config.Listen.effectiveMaxRequestBodyBytes())
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			slog.Warn("Request body exceeds limit", "limit_bytes", maxErr.Limit, "request_id", requestID)
			writeError(rc, audit, http.StatusRequestEntityTooLarge, "payload_too_large", "request_body_too_large", "request body exceeds the maximum allowed size")
			return
		}
		p.writeBodyReadError(rc, audit, err)
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
	providerName := resolveProviderName(r.URL.Path, openaiCompatName)

	// Per-key authorization. With no scopes configured the call is unrestricted
	// (backwards compatible); a configured allow-list rejects requests outside
	// the key's scope with HTTP 403. The audit entry already carries the key ID
	// from auth, so the structured-error fields and the existing audit emission
	// give end-to-end correlation by request_id. modelForScopeCheck consults
	// the URL for providers (vertex, bedrock) that carry the model there rather
	// than in the body.
	scopeModel := modelForScopeCheck(providerName, r.URL.Path, bodyBytes)
	if denial := enforceScopes(keyScopes, providerName, scopeModel, r.URL.Path); denial != nil {
		audit.Provider = providerName
		audit.Model = scopeModel
		slog.Warn("Per-key scope denied", "client", clientKeyID, "field", denial.Field, "value", denial.Value, "request_id", requestID)
		writeError(rc, audit, http.StatusForbidden, "forbidden", denial.Code, "request not permitted by API key scope")
		return
	}

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
	} else if isVertexPath(r.URL.Path) {
		audit.Provider = "vertex"
		if p.vertexTarget == nil {
			writeError(rc, audit, http.StatusNotFound, "not_found", "vertex_disabled", "vertex provider not configured")
		} else {
			p.handleVertex(rc, r, bodyBytes, philter_context, philter_document_id, philter_policy_name, audit, route.Outbound)
		}
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
}

// resolveProviderName returns the canonical provider name for a request, the
// same name that ends up in audit.Provider. Path-based dispatching the proxy
// already does (see the handler if/else below) is centralized here so per-key
// scope enforcement can decide BEFORE the request reaches a handler. The
// caller passes in the openai-compatible name (when matched) since that has
// already been resolved by stripping the URL prefix.
func resolveProviderName(path, openaiCompatName string) string {
	if openaiCompatName != "" {
		return openaiCompatName
	}
	if strings.HasPrefix(path, "/v1/messages") {
		return "anthropic"
	}
	// Vertex must come before the generic Gemini check: Vertex paths also
	// contain "generatecontent" but resolve to a separate provider with a
	// different endpoint and auth model.
	if isVertexPath(path) {
		return "vertex"
	}
	if strings.Contains(strings.ToLower(path), "generatecontent") {
		return "gemini"
	}
	if path == "/api/generate" || path == "/api/chat" {
		return "ollama"
	}
	if isAzurePath(path) {
		return "azure"
	}
	if isBedrockPath(path) {
		return "bedrock"
	}
	return "openai"
}

// scopeDenial describes why a per-key scope check rejected a request. The
// Code is the stable structured error sub-code returned to the client; the
// Field/Value pair feeds the operator-visible log message.
type scopeDenial struct {
	Code  string
	Field string // "provider", "model", "path"
	Value string
}

// modelForScopeCheck returns the request's model identifier for per-key
// scope enforcement. Most providers carry the model in the request body;
// Vertex and Bedrock embed it in the URL path. Without this dispatch, a
// per-key `scopes.models` allow-list configured for a Vertex or Bedrock key
// would deny every request (the body has no `model` field, so the value the
// scope check sees would be empty).
func modelForScopeCheck(provider, path string, bodyBytes []byte) string {
	switch provider {
	case "vertex":
		if m := vertexModelFromPath(path); m != "" {
			return m
		}
	case "bedrock":
		if m := bedrockModelFromPath(path); m != "" {
			return m
		}
	}
	return extractModel(bodyBytes)
}

// matchesScopeEntry implements the matching grammar for one Models / Paths /
// Providers entry. For Providers and Models, the entry is an exact string
// unless it ends in `*`, in which case it is a prefix match (e.g. `gpt-4*`).
// For Paths, the entry is always a prefix match (a key's scope of
// `/v1/chat/completions` matches `/v1/chat/completions` and any sub-path).
func matchesScopeEntry(entry, value string, alwaysPrefix bool) bool {
	if entry == value {
		return true
	}
	if alwaysPrefix {
		return strings.HasPrefix(value, entry)
	}
	if strings.HasSuffix(entry, "*") {
		return strings.HasPrefix(value, strings.TrimSuffix(entry, "*"))
	}
	return false
}

// enforceScopes checks a request against a key's per-key scope allow-lists.
// Returns nil when allowed (including when the key has no scopes configured,
// preserving backwards-compatible full access). On denial returns a scopeDenial
// describing which dimension failed; the caller is responsible for writing
// the 403 error response.
//
// Each dimension is independent: a non-empty allow-list on one axis only
// restricts that axis; other axes remain unrestricted unless they too have
// non-empty lists. An empty (or nil) slice on an axis means "any value is
// allowed on this axis."
func enforceScopes(scopes *APIKeyScopes, provider, model, path string) *scopeDenial {
	if scopes == nil {
		return nil
	}
	if len(scopes.Providers) > 0 {
		ok := false
		for _, entry := range scopes.Providers {
			if matchesScopeEntry(entry, provider, false) {
				ok = true
				break
			}
		}
		if !ok {
			return &scopeDenial{Code: "scope_denied_provider", Field: "provider", Value: provider}
		}
	}
	if len(scopes.Models) > 0 {
		// An empty model field on the request means the request did not
		// specify a model. When the key has a model allow-list configured,
		// require a model so we can authorize against it.
		if model == "" {
			return &scopeDenial{Code: "scope_denied_model", Field: "model", Value: ""}
		}
		ok := false
		for _, entry := range scopes.Models {
			if matchesScopeEntry(entry, model, false) {
				ok = true
				break
			}
		}
		if !ok {
			return &scopeDenial{Code: "scope_denied_model", Field: "model", Value: model}
		}
	}
	if len(scopes.Paths) > 0 {
		ok := false
		for _, entry := range scopes.Paths {
			if matchesScopeEntry(entry, path, true) {
				ok = true
				break
			}
		}
		if !ok {
			return &scopeDenial{Code: "scope_denied_path", Field: "path", Value: path}
		}
	}
	return nil
}

// handshakeTimeoutListener wraps a tls.Listener and bounds how long any single
// client may take to complete the TLS handshake.
//
// net/http's implicit handshake timeout is derived from min(ReadHeaderTimeout,
// ReadTimeout, WriteTimeout) and is not independently configurable. We want
// an independent, operator-set value -- so this listener performs the
// handshake EAGERLY (one goroutine per accepted conn, so slow handshakes do
// not stall the accept loop) with its own deadline, and only releases the
// connection to net/http once the handshake has succeeded. Failed handshakes
// are closed and never reach net/http. After a successful handshake the
// underlying TCP deadline is cleared, so this does not affect post-handshake
// reads or response streaming.
//
// timeout <= 0 disables handshake gating (conns pass through unchanged).
//
// A buffered `sem` channel bounds the number of in-flight handshake goroutines
// (maxConcurrent). When the ceiling is reached the accept loop drops the new
// connection immediately rather than spawning an unbounded goroutine, so a
// TCP+ClientHello flood cannot hold tens of thousands of goroutines each pinned
// for the full handshake timeout. The slot is released as soon as the handshake
// resolves -- before the (possibly blocking) hand-off to net/http -- so the
// ceiling bounds only the handshake phase and never throttles established
// connections. onShed, if set, is invoked once per dropped connection.
//
// Construct via newHandshakeTimeoutListener so the internal channels and
// accept goroutine are wired before any Accept or Close call.
type handshakeTimeoutListener struct {
	net.Listener
	timeout time.Duration

	sem    chan struct{}
	onShed func()

	// onSlotAcquired, if set, is invoked synchronously the instant a connection
	// acquires a handshake slot. It is a test hook (nil in production) that lets
	// tests synchronize on slot occupancy instead of sleeping. It is set before
	// the accept goroutine starts, so reads from acceptLoop are race-free.
	onSlotAcquired func()

	ready     chan acceptResult
	closing   chan struct{}
	closeOnce sync.Once
}

type acceptResult struct {
	c   net.Conn
	err error
}

func newHandshakeTimeoutListener(inner net.Listener, timeout time.Duration, maxConcurrent int, onShed func()) *handshakeTimeoutListener {
	return newHandshakeTimeoutListenerWithHook(inner, timeout, maxConcurrent, onShed, nil)
}

// newHandshakeTimeoutListenerWithHook is newHandshakeTimeoutListener plus an
// onSlotAcquired test hook fired immediately after a connection acquires a
// handshake slot. Production code uses the hook-less constructor.
func newHandshakeTimeoutListenerWithHook(inner net.Listener, timeout time.Duration, maxConcurrent int, onShed, onSlotAcquired func()) *handshakeTimeoutListener {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrentTLSHandshakes
	}
	l := &handshakeTimeoutListener{
		Listener:       inner,
		timeout:        timeout,
		sem:            make(chan struct{}, maxConcurrent),
		onShed:         onShed,
		onSlotAcquired: onSlotAcquired,
		ready:          make(chan acceptResult),
		closing:        make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func (l *handshakeTimeoutListener) acceptLoop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			// Unconditionally deliver the final error so the consumer's
			// blocked Accept unblocks and net/http's Serve loop exits.
			// l.closing is for in-flight handshake goroutines, not for
			// this terminal hand-off.
			l.ready <- acceptResult{err: err}
			return
		}
		select {
		case l.sem <- struct{}{}:
			if l.onSlotAcquired != nil {
				l.onSlotAcquired()
			}
			go l.handshake(c)
		default:
			// Handshake concurrency ceiling reached: shed this connection
			// immediately instead of spawning an unbounded goroutine. The
			// accept loop keeps running so established peers are unaffected.
			c.Close()
			if l.onShed != nil {
				l.onShed()
			}
		}
	}
}

func (l *handshakeTimeoutListener) handshake(c net.Conn) {
	// Perform the handshake, then release the semaphore slot BEFORE the
	// (possibly blocking) hand-off to net/http, so the ceiling bounds only the
	// handshake phase -- successful conns waiting to be Accepted do not hold a
	// slot.
	conn, ok := l.doHandshake(c)
	<-l.sem
	if !ok {
		return
	}
	select {
	case l.ready <- acceptResult{c: conn}:
	case <-l.closing:
		conn.Close()
	}
}

// doHandshake completes the TLS handshake under the configured deadline,
// returning the ready connection and true on success, or (nil, false) when the
// connection was dropped (slow/invalid handshake, or a deadline error). When
// gating is disabled or the conn is not a *tls.Conn, it passes through.
func (l *handshakeTimeoutListener) doHandshake(c net.Conn) (net.Conn, bool) {
	if l.timeout <= 0 {
		return c, true
	}
	tc, ok := c.(*tls.Conn)
	if !ok {
		return c, true
	}
	if err := tc.SetDeadline(time.Now().Add(l.timeout)); err != nil {
		tc.Close()
		return nil, false
	}
	if err := tc.HandshakeContext(context.Background()); err != nil {
		// Slow/incomplete/invalid handshake: drop silently. The listener
		// loop is unaffected; net/http never sees this conn.
		tc.Close()
		return nil, false
	}
	if err := tc.SetDeadline(time.Time{}); err != nil {
		tc.Close()
		return nil, false
	}
	return tc, true
}

func (l *handshakeTimeoutListener) Accept() (net.Conn, error) {
	r, ok := <-l.ready
	if !ok {
		return nil, net.ErrClosed
	}
	return r.c, r.err
}

func (l *handshakeTimeoutListener) Close() error {
	l.closeOnce.Do(func() { close(l.closing) })
	return l.Listener.Close()
}

// hardenedServer builds an http.Server with inbound request-hardening applied:
// a header read deadline (slowloris mitigation) and a header size cap, with
// secure defaults when unset. WriteTimeout is deliberately omitted so streaming
// responses can run arbitrarily long; ReadTimeout (whole-request, incl. body)
// is opt-in and never affects response writes.
func hardenedServer(addr string, handler http.Handler, cfg ListenConfig) *http.Server {
	readHeaderTimeoutMs := cfg.ReadHeaderTimeoutMs
	if readHeaderTimeoutMs == 0 {
		readHeaderTimeoutMs = DefaultReadHeaderTimeoutMs
	}
	maxHeaderBytes := cfg.MaxHeaderBytes
	if maxHeaderBytes == 0 {
		maxHeaderBytes = DefaultMaxHeaderBytes
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: time.Duration(readHeaderTimeoutMs) * time.Millisecond,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	if cfg.ReadTimeoutMs > 0 {
		srv.ReadTimeout = time.Duration(cfg.ReadTimeoutMs) * time.Millisecond
	}
	return srv
}

// buildInboundMTLSConfig builds the TLS config that requires and verifies a
// client certificate against the CA at clientCAPath. Returned as (config, error)
// rather than exiting, so it is testable and callers control failure handling.
func buildInboundMTLSConfig(clientCAPath string) (*tls.Config, error) {
	caCert, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client CA certificate %s: %w", clientCAPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse client CA certificate %s", clientCAPath)
	}
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func (p *Proxy) handleOllamaGenerate(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	var o OllamaGenerateRequest
	if err := json.Unmarshal(bodyBytes, &o); err != nil {
		p.writeBadJSON(w, audit, err)
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
		p.writeMarshalFailed(w, audit, err)
		return
	}

	if outbound.Enabled {
		p.forwardWithOutboundScan(w, r, p.ollamaTarget, p.ollamaClient, j, "ollama",
			context, documentId, policyName, outbound, audit, p.scanOllamaGenerateResponse)
		return
	}
	p.forwardToProvider(w, r, p.ollamaTarget, p.ollamaClient, j, "ollama", audit)
}

func (p *Proxy) handleOllamaChat(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	var o OllamaChatRequest
	if err := json.Unmarshal(bodyBytes, &o); err != nil {
		p.writeBadJSON(w, audit, err)
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
		p.writeMarshalFailed(w, audit, err)
		return
	}

	if outbound.Enabled {
		p.forwardWithOutboundScan(w, r, p.ollamaTarget, p.ollamaClient, j, "ollama",
			context, documentId, policyName, outbound, audit, p.scanOllamaChatResponse)
		return
	}
	p.forwardToProvider(w, r, p.ollamaTarget, p.ollamaClient, j, "ollama", audit)
}

func (p *Proxy) handleGeminiNative(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	p.handleGeminiShaped(w, r, bodyBytes, context, documentId, policyName, audit, outbound, p.geminiTarget, p.geminiClient, "gemini")
}

// handleGeminiShaped redacts a Gemini-shaped request and forwards it to the
// given target/client/providerName. Used by the public Gemini provider and by
// Vertex AI (whose request and response bodies are the same Gemini schema).
func (p *Proxy) handleGeminiShaped(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig, target *url.URL, client *http.Client, providerName string) {
	var g GeminiRequest
	if err := json.Unmarshal(bodyBytes, &g); err != nil {
		p.writeBadJSON(w, audit, err)
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
		p.writeMarshalFailed(w, audit, err)
		return
	}

	if outbound.Enabled {
		p.forwardWithOutboundScan(w, r, target, client, j, providerName,
			context, documentId, policyName, outbound, audit, p.scanGeminiResponse)
		return
	}
	p.forwardToProvider(w, r, target, client, j, providerName, audit)
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
		p.writeBadJSON(w, audit, err)
		return
	}

	if rawModel, ok := root["model"]; ok {
		var m string
		_ = json.Unmarshal(rawModel, &m)
		audit.Model = m
	}

	// Redact the text-bearing fields appropriate to this endpoint (chat
	// messages, embeddings/moderations input, Responses input/instructions,
	// image/completions prompt, ...). All non-redacted top-level fields are
	// preserved.
	if err := p.redactOpenAIEndpoint(r.Context(), classifyOpenAIEndpoint(r.URL.Path), root, context, documentId, policyName, audit); err != nil {
		p.philterError(w, audit, err)
		return
	}

	j, err := json.Marshal(root)
	if err != nil {
		p.writeMarshalFailed(w, audit, err)
		return
	}

	if outbound.Enabled {
		p.forwardWithOutboundScan(w, r, target, client, j, provider,
			context, documentId, policyName, outbound, audit, p.scanOpenAIResponse)
		return
	}
	p.forwardToProvider(w, r, target, client, j, provider, audit)
}

func (p *Proxy) handleAnthropic(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	var a AnthropicRequest
	if err := json.Unmarshal(bodyBytes, &a); err != nil {
		p.writeBadJSON(w, audit, err)
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
		p.writeMarshalFailed(w, audit, err)
		return
	}

	if outbound.Enabled {
		p.forwardWithOutboundScan(w, r, p.anthropicTarget, p.anthropicClient, j, "anthropic",
			context, documentId, policyName, outbound, audit, p.scanAnthropicResponse)
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

// version is the build version of the binary. It defaults to "dev" for plain
// `go build` and is overridden at release time via the linker, e.g.:
//
//	go build -ldflags "-X main.version=v1.0.0" .
//
// Reported by the --version flag and logged at startup.
var version = "dev"

// versionString returns a human-readable version line. When the binary carries
// module/VCS metadata (the default for `go build`), it appends the short commit
// revision (with a +dirty marker for builds with uncommitted changes) and the
// Go toolchain version, so even un-stamped local builds identify themselves.
func versionString() string {
	v := version
	rev, dirty, goVer := buildVCSInfo()
	var extra []string
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		if dirty {
			rev += "+dirty"
		}
		extra = append(extra, "commit "+rev)
	}
	if goVer != "" {
		extra = append(extra, "built with "+goVer)
	}
	if len(extra) > 0 {
		v += " (" + strings.Join(extra, ", ") + ")"
	}
	return "philter-ai-proxy " + v
}

// buildVCSInfo reads the VCS revision, dirty flag, and Go toolchain version
// embedded by the Go toolchain at build time. Values are empty when the binary
// was built without module/VCS info.
func buildVCSInfo() (revision string, dirty bool, goVersion string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false, ""
	}
	goVersion = info.GoVersion
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	return revision, dirty, goVersion
}

// cliOptions holds the parsed command-line flags.
type cliOptions struct {
	configPath   string
	validateOnly bool
	showVersion  bool
}

// parseCLI parses the proxy's command-line flags. It is split out from main so
// it can be tested without invoking the full startup path. `args` is the
// process's argv tail (os.Args[1:]); `errOut` receives flag-package usage and
// error output. configPath falls back to PHILTER_PROXY_CONFIG when --config is
// not supplied.
func parseCLI(args []string, errOut io.Writer) (cliOptions, error) {
	fs := flag.NewFlagSet("philter-ai-proxy", flag.ContinueOnError)
	fs.SetOutput(errOut)
	cfgFlag := fs.String("config", "", "path to the YAML config file (or set PHILTER_PROXY_CONFIG)")
	validateFlag := fs.Bool("validate-config", false, "load and validate the config, then exit (0 = ok, 1 = invalid)")
	versionFlag := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return cliOptions{}, err
	}
	path := *cfgFlag
	if path == "" {
		path = os.Getenv("PHILTER_PROXY_CONFIG")
	}
	return cliOptions{configPath: path, validateOnly: *validateFlag, showVersion: *versionFlag}, nil
}

// runValidateConfig implements `--validate-config`. It loads the config from
// `path` and reports the result. Returns 0 on success, 1 on failure. The
// success line goes to `out` and any error to `errOut`; using io.Writers lets
// tests capture both.
func runValidateConfig(path string, out, errOut io.Writer) int {
	if _, err := loadConfig(path); err != nil {
		fmt.Fprintf(errOut, "config invalid: %s\n", err)
		return 1
	}
	fmt.Fprintf(out, "config OK: %s\n", path)
	return 0
}

func main() {

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	opts, err := parseCLI(os.Args[1:], os.Stderr)
	if err != nil {
		// flag package already printed a usage hint to stderr.
		os.Exit(2)
	}

	if opts.showVersion {
		fmt.Println(versionString())
		os.Exit(0)
	}

	if opts.validateOnly {
		os.Exit(runValidateConfig(opts.configPath, os.Stdout, os.Stderr))
	}

	cfg, err := loadConfig(opts.configPath)
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

	philterHTTPClient := disableRedirects(&http.Client{
		Transport: newProviderTransport(philterTLSConfig, cfg.Philter.Timeouts),
	})
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
		clients[i] = disableRedirects(&http.Client{
			Transport: newProviderTransport(tlsCfg, prov.config.Timeouts),
		})
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
			disableRedirects(&http.Client{Transport: newProviderTransport(tlsCfg, pc.Timeouts)}),
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
			disableRedirects(&http.Client{Transport: newProviderTransport(tlsCfg, cfg.Providers.Azure.Timeouts)}),
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

	var vertexTarget *url.URL
	var vertexClient *http.Client
	var vertexTokenSrc tokenSource
	if cfg.Providers.Vertex.Project != "" {
		vertexTarget, err = vertexTargetURL(cfg.Providers.Vertex)
		if err != nil {
			slog.Error("Invalid Vertex configuration", "error", err)
			os.Exit(1)
		}
		verify := true
		if cfg.Providers.Vertex.TLSVerify != nil {
			verify = *cfg.Providers.Vertex.TLSVerify
		}
		tlsCfg, err := buildTLSConfig(!verify, "")
		if err != nil {
			slog.Error("Vertex TLS configuration error", "error", err)
			os.Exit(1)
		}
		vertexClient = instrumentTransport(
			disableRedirects(&http.Client{Transport: newProviderTransport(tlsCfg, cfg.Providers.Vertex.Timeouts)}),
			tracingActive, "provider.vertex",
		)
		ts, err := newVertexTokenProvider(context.Background())
		if err != nil {
			slog.Error("Failed to initialize Vertex ADC credential", "error", err)
			os.Exit(1)
		}
		vertexTokenSrc = ts
		slog.Info("Vertex AI provider configured",
			"project", cfg.Providers.Vertex.Project,
			"location", cfg.Providers.Vertex.Location,
			"target", vertexTarget.String())
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

	var proxyConcurrency *ConcurrencyLimiter
	if cfg.Listen.MaxConcurrentRequests > 0 {
		proxyConcurrency = newConcurrencyLimiter(cfg.Listen.MaxConcurrentRequests)
		slog.Info("Concurrency guard enabled", "global", cfg.Listen.MaxConcurrentRequests)
	}
	if proxyMetrics != nil {
		proxyMetrics.concurrencyLimit.WithLabelValues("global").Set(float64(cfg.Listen.MaxConcurrentRequests))
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
		vertexTarget:            vertexTarget,
		vertexClient:            vertexClient,
		vertexTokenSource:       vertexTokenSrc,
		openaiCompatibleTargets: openaiCompatTargets,
		openaiCompatibleClients: openaiCompatClients,
		philter:                 philterClient,
		auditLogger:             auditLogger,
		metrics:                 proxyMetrics,
		keyStore:                keyStoreInstance,
		concurrency:             proxyConcurrency,
		trustedProxies:          parseTrustedProxies(cfg.Listen.TrustedProxies),
	}
	port := fmt.Sprintf("%d", cfg.Listen.Port)
	shutdownTimeoutSec := cfg.Listen.ShutdownTimeout

	srv := hardenedServer(":"+port, instrumentHandler(p, tracingActive), cfg.Listen)

	// mTLS: require and verify client certificates when clientCA is configured.
	if cfg.Listen.ClientCA != "" {
		tlsCfg, err := buildInboundMTLSConfig(cfg.Listen.ClientCA)
		if err != nil {
			slog.Error("mTLS setup failed", "error", err)
			os.Exit(1)
		}
		srv.TLSConfig = tlsCfg
		slog.Info("mTLS enabled", "clientCA", cfg.Listen.ClientCA)
	}

	var metricsSrv *http.Server
	if cfg.Metrics.Enabled {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(metricsReg, promhttp.HandlerOpts{}))
		metricsSrv = hardenedServer(fmt.Sprintf(":%d", cfg.Metrics.Port), mux, cfg.Listen)
		go func() {
			slog.Info("Started metrics server", "port", cfg.Metrics.Port)
			if err := metricsSrv.ListenAndServe(); err != http.ErrServerClosed {
				slog.Warn("Metrics server stopped", "error", err)
			}
		}()
	}

	tlsHandshakeTimeout := cfg.Listen.effectiveTLSHandshakeTimeout()
	maxTLSHandshakes := cfg.Listen.effectiveMaxConcurrentTLSHandshakes()
	var onHandshakeShed func()
	if proxyMetrics != nil {
		onHandshakeShed = proxyMetrics.tlsHandshakesShed.Inc
	}

	// Build the TLS listener chain explicitly so handshakeTimeoutListener can
	// wrap the inner tls.Listener and enforce its own handshake deadline
	// (net/http's implicit deadline is derived from ReadHeaderTimeout and
	// cannot be independently configured). We then call srv.Serve, not
	// srv.ServeTLS, since ServeTLS would unconditionally re-wrap with another
	// tls.NewListener.
	cert, err := resolveServerCertificate(cfg.Listen)
	if err != nil {
		slog.Error("TLS certificate error", "error", err)
		os.Exit(1)
	}
	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{}
	}
	if srv.TLSConfig.MinVersion == 0 {
		srv.TLSConfig.MinVersion = tls.VersionTLS12
	}
	srv.TLSConfig.Certificates = append(srv.TLSConfig.Certificates, cert)

	tcpListener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		slog.Error("Listen error", "error", err)
		os.Exit(1)
	}
	tlsListener := newHandshakeTimeoutListener(tls.NewListener(tcpListener, srv.TLSConfig), tlsHandshakeTimeout, maxTLSHandshakes, onHandshakeShed)

	go func() {
		slog.Info("Started philter-ai-proxy", "version", version, "port", port,
			"tlsHandshakeTimeoutMs", tlsHandshakeTimeout.Milliseconds(),
			"maxConcurrentTLSHandshakes", maxTLSHandshakes)
		if err := srv.Serve(tlsListener); err != http.ErrServerClosed {
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
