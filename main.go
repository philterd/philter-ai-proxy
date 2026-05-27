package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	philterClient   *http.Client
	auditLogger     *slog.Logger
	metrics         *ProxyMetrics
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

func (p *Proxy) philterError(w http.ResponseWriter, err error) {
	slog.Error("Philter request failed", "error", err)
	if p.metrics != nil {
		p.metrics.philterErrors.Inc()
	}
	http.Error(w, "philter request failed", http.StatusBadGateway)
}

func (p *Proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if p.config == nil || p.philterClient == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", p.config.Philter.Endpoint, nil)
	resp, err := p.philterClient.Do(req)
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

func (p *Proxy) forwardToProvider(w http.ResponseWriter, origReq *http.Request, target *url.URL, client *http.Client, body []byte, provider string) {
	targetURL := *target
	targetURL.Path = origReq.URL.Path
	targetURL.RawQuery = origReq.URL.RawQuery

	req, err := http.NewRequest(origReq.Method, targetURL.String(), bytes.NewReader(body))
	if err != nil {
		slog.Error("Failed to create provider request", "error", err, "path", origReq.URL.Path)
		http.Error(w, "failed to create provider request", http.StatusInternalServerError)
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
		slog.Error("Provider request failed", "error", err, "url", safeURL)
		if p.metrics != nil {
			p.metrics.upstreamErrors.WithLabelValues(provider, "502").Inc()
		}
		http.Error(w, "provider request failed", http.StatusBadGateway)
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
	)
}

type Span struct {
	FilterType string  `json:"filterType"`
	Confidence float64 `json:"confidence"`
}

type Explanation struct {
	AppliedSpans []Span `json:"appliedSpans"`
}

type ExplainResponse struct {
	FilteredText string      `json:"filteredText"`
	Context      string      `json:"context"`
	DocumentId   string      `json:"documentId"`
	Explanation  Explanation `json:"explanation"`
}

type FilterResponse struct {
	FilteredText     string
	Context          string
	DocumentId       string
	EntityCount      int
	EntityTypes      []string
	EntityTypeCounts map[string]int
	Latency          time.Duration
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

func Filter(client *http.Client, endpoint string, input string, context string, documentId string, policyName string) (FilterResponse, error) {
	base, err := url.Parse(endpoint + "/api/explain")
	if err != nil {
		return FilterResponse{}, fmt.Errorf("failed to parse Philter endpoint: %w", err)
	}

	params := url.Values{}
	params.Add("c", context)
	params.Add("d", documentId)
	params.Add("p", policyName)
	base.RawQuery = params.Encode()

	request, err := http.NewRequest("POST", base.String(), bytes.NewReader([]byte(input)))
	if err != nil {
		return FilterResponse{}, fmt.Errorf("failed to create Philter request: %w", err)
	}
	request.Header.Add("Content-Type", "text/plain")

	start := time.Now()
	response, err := client.Do(request)
	latency := time.Since(start)
	if err != nil {
		return FilterResponse{}, fmt.Errorf("Philter request failed: %w", err)
	}
	defer response.Body.Close()

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return FilterResponse{}, fmt.Errorf("failed to read Philter response: %w", err)
	}

	var explainResp ExplainResponse
	if err := json.Unmarshal(responseData, &explainResp); err != nil {
		return FilterResponse{}, fmt.Errorf("failed to parse Philter response: %w", err)
	}

	typesSet := make(map[string]struct{})
	typeCounts := make(map[string]int)
	for _, span := range explainResp.Explanation.AppliedSpans {
		typesSet[span.FilterType] = struct{}{}
		typeCounts[span.FilterType]++
	}
	entityTypes := make([]string, 0, len(typesSet))
	for t := range typesSet {
		entityTypes = append(entityTypes, t)
	}

	return FilterResponse{
		FilteredText:     explainResp.FilteredText,
		Context:          explainResp.Context,
		DocumentId:       explainResp.DocumentId,
		EntityCount:      len(explainResp.Explanation.AppliedSpans),
		EntityTypes:      entityTypes,
		EntityTypeCounts: typeCounts,
		Latency:          latency,
	}, nil
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

func redactAny(client *http.Client, v any, endpoint, ctx, docID, policy string, audit *AuditEntry) (any, error) {
	switch val := v.(type) {
	case string:
		if val != "" {
			fr, err := Filter(client, endpoint, val, ctx, docID, policy)
			if err != nil {
				return nil, err
			}
			audit.recordFilterResult(fr)
			return fr.FilteredText, nil
		}
		return val, nil
	case map[string]any:
		for k, elem := range val {
			redacted, err := redactAny(client, elem, endpoint, ctx, docID, policy, audit)
			if err != nil {
				return nil, err
			}
			val[k] = redacted
		}
		return val, nil
	case []any:
		for i, elem := range val {
			redacted, err := redactAny(client, elem, endpoint, ctx, docID, policy, audit)
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

func redactJSONArguments(client *http.Client, arguments string, endpoint, ctx, docID, policy string, audit *AuditEntry) (string, error) {
	var parsed any
	if err := json.Unmarshal([]byte(arguments), &parsed); err != nil {
		fr, err := Filter(client, endpoint, arguments, ctx, docID, policy)
		if err != nil {
			return "", err
		}
		audit.recordFilterResult(fr)
		return fr.FilteredText, nil
	}
	result, err := redactAny(client, parsed, endpoint, ctx, docID, policy, audit)
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

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path == "/health" {
		p.handleHealth(w, r)
		return
	}

	if p.metrics != nil {
		p.metrics.activeRequests.Inc()
		defer p.metrics.activeRequests.Dec()
	}
	start := time.Now()

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	model := extractModel(bodyBytes)
	route := matchRoute(p.config, r.URL.Path, model, r.Header.Get)

	philter_endpoint := p.config.Philter.Endpoint
	philter_context := route.Context
	philter_document_id := uuid.New().String()
	philter_policy_name := route.Policy

	audit := &AuditEntry{
		RequestID:  uuid.New().String(),
		Direction:  "inbound",
		PolicyName: philter_policy_name,
		DocumentID: philter_document_id,
		ClientIP:   clientIP(r),
	}

	rc := newResponseCapture(w)

	if strings.HasPrefix(r.URL.Path, "/v1/messages") {
		audit.Provider = "anthropic"
		p.handleAnthropic(rc, r, bodyBytes, philter_endpoint, philter_context, philter_document_id, philter_policy_name, audit)
	} else if strings.Contains(strings.ToLower(r.URL.Path), "generatecontent") {
		audit.Provider = "gemini"
		p.handleGeminiNative(rc, r, bodyBytes, philter_endpoint, philter_context, philter_document_id, philter_policy_name, audit)
	} else if r.URL.Path == "/api/generate" {
		audit.Provider = "ollama"
		p.handleOllamaGenerate(rc, r, bodyBytes, philter_endpoint, philter_context, philter_document_id, philter_policy_name, audit)
	} else if r.URL.Path == "/api/chat" {
		audit.Provider = "ollama"
		p.handleOllamaChat(rc, r, bodyBytes, philter_endpoint, philter_context, philter_document_id, philter_policy_name, audit)
	} else {
		audit.Provider = "openai"
		p.handleOpenAI(rc, r, bodyBytes, philter_endpoint, philter_context, philter_document_id, philter_policy_name, audit)
	}

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
	}
}

func (p *Proxy) handleOllamaGenerate(w http.ResponseWriter, r *http.Request, bodyBytes []byte, philter_endpoint string, context string, documentId string, policyName string, audit *AuditEntry) {
	var o OllamaGenerateRequest
	if err := json.Unmarshal(bodyBytes, &o); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.Model = o.Model

	if o.Prompt != "" {
		fr, err := Filter(p.philterClient, philter_endpoint, o.Prompt, context, documentId, policyName)
		if err != nil {
			p.philterError(w, err)
			return
		}
		o.Prompt = fr.FilteredText
		audit.recordFilterResult(fr)
	}

	if o.System != "" {
		fr, err := Filter(p.philterClient, philter_endpoint, o.System, context, documentId, policyName)
		if err != nil {
			p.philterError(w, err)
			return
		}
		o.System = fr.FilteredText
		audit.recordFilterResult(fr)
	}

	j, err := json.Marshal(o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p.forwardToProvider(w, r, p.ollamaTarget, p.ollamaClient, j, "ollama")
}

func (p *Proxy) handleOllamaChat(w http.ResponseWriter, r *http.Request, bodyBytes []byte, philter_endpoint string, context string, documentId string, policyName string, audit *AuditEntry) {
	var o OllamaChatRequest
	if err := json.Unmarshal(bodyBytes, &o); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.Model = o.Model

	for i := range o.Messages {
		fr, err := Filter(p.philterClient, philter_endpoint, o.Messages[i].Content, context, documentId, policyName)
		if err != nil {
			p.philterError(w, err)
			return
		}
		o.Messages[i].Content = fr.FilteredText
		audit.recordFilterResult(fr)
	}

	j, err := json.Marshal(o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p.forwardToProvider(w, r, p.ollamaTarget, p.ollamaClient, j, "ollama")
}

func (p *Proxy) handleGeminiNative(w http.ResponseWriter, r *http.Request, bodyBytes []byte, philter_endpoint string, context string, documentId string, policyName string, audit *AuditEntry) {
	var g GeminiRequest
	if err := json.Unmarshal(bodyBytes, &g); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var filterErr error
loop:
	for i := range g.Contents {
		for j := range g.Contents[i].Parts {
			part := &g.Contents[i].Parts[j]
			if part.Text != "" {
				fr, err := Filter(p.philterClient, philter_endpoint, part.Text, context, documentId, policyName)
				if err != nil {
					filterErr = err
					break loop
				}
				part.Text = fr.FilteredText
				audit.recordFilterResult(fr)
			}
			if part.FunctionResponse != nil && part.FunctionResponse.Response != nil {
				if _, err := redactAny(p.philterClient, part.FunctionResponse.Response, philter_endpoint, context, documentId, policyName, audit); err != nil {
					filterErr = err
					break loop
				}
			}
		}
	}
	if filterErr != nil {
		p.philterError(w, filterErr)
		return
	}

	j, err := json.Marshal(g)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p.forwardToProvider(w, r, p.geminiTarget, p.geminiClient, j, "gemini")
}

func (p *Proxy) handleOpenAI(w http.ResponseWriter, r *http.Request, bodyBytes []byte, philter_endpoint string, context string, documentId string, policyName string, audit *AuditEntry) {
	var o OpenAIRequest
	if err := json.Unmarshal(bodyBytes, &o); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.Model = o.Model

	for i := range o.Messages {
		msg := &o.Messages[i]

		if len(msg.Content) > 0 {
			var s string
			if json.Unmarshal(msg.Content, &s) == nil && s != "" {
				fr, err := Filter(p.philterClient, philter_endpoint, s, context, documentId, policyName)
				if err != nil {
					p.philterError(w, err)
					return
				}
				msg.Content, _ = json.Marshal(fr.FilteredText)
				audit.recordFilterResult(fr)
			}
		}

		for j := range msg.ToolCalls {
			tc := &msg.ToolCalls[j]
			if tc.Function.Arguments != "" {
				redacted, err := redactJSONArguments(p.philterClient, tc.Function.Arguments, philter_endpoint, context, documentId, policyName, audit)
				if err != nil {
					p.philterError(w, err)
					return
				}
				tc.Function.Arguments = redacted
			}
		}
	}

	j, err := json.Marshal(o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p.forwardToProvider(w, r, p.openaiTarget, p.openaiClient, j, "openai")
}

func (p *Proxy) handleAnthropic(w http.ResponseWriter, r *http.Request, bodyBytes []byte, philter_endpoint string, context string, documentId string, policyName string, audit *AuditEntry) {
	var a AnthropicRequest
	if err := json.Unmarshal(bodyBytes, &a); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.Model = a.Model

	var filterErr error

	if a.System != "" {
		fr, err := Filter(p.philterClient, philter_endpoint, a.System, context, documentId, policyName)
		if err != nil {
			p.philterError(w, err)
			return
		}
		a.System = fr.FilteredText
		audit.recordFilterResult(fr)
	}

msgloop:
	for i := range a.Messages {
		switch v := a.Messages[i].Content.(type) {
		case string:
			fr, err := Filter(p.philterClient, philter_endpoint, v, context, documentId, policyName)
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
							fr, err := Filter(p.philterClient, philter_endpoint, text, context, documentId, policyName)
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
								fr, err := Filter(p.philterClient, philter_endpoint, c, context, documentId, policyName)
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
											fr, err := Filter(p.philterClient, philter_endpoint, text, context, documentId, policyName)
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
		p.philterError(w, filterErr)
		return
	}

	j, err := json.Marshal(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p.forwardToProvider(w, r, p.anthropicTarget, p.anthropicClient, j, "anthropic")
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

	philterClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: philterTLSConfig,
		},
	}

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

	var proxyMetrics *ProxyMetrics
	var metricsReg *prometheus.Registry
	if cfg.Metrics.Enabled {
		metricsReg = prometheus.NewRegistry()
		proxyMetrics = newMetrics(metricsReg)
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
		philterClient:   philterClient,
		auditLogger:     auditLogger,
		metrics:         proxyMetrics,
	}

	port := fmt.Sprintf("%d", cfg.Listen.Port)
	cert_file := cfg.Listen.Cert
	key_file := cfg.Listen.Key
	shutdownTimeoutSec := cfg.Listen.ShutdownTimeout

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: p,
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
