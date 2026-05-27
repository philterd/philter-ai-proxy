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
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
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

type GeminiPart struct {
	Text string `json:"text"`
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
	openaiTarget    *url.URL
	anthropicTarget *url.URL
	geminiTarget    *url.URL
	ollamaTarget    *url.URL
	openaiProxy     *httputil.ReverseProxy
	anthropicProxy  *httputil.ReverseProxy
	geminiProxy     *httputil.ReverseProxy
	ollamaProxy     *httputil.ReverseProxy
	philterClient   *http.Client
	auditLogger     *slog.Logger
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
	HTTPStatus     int           `json:"http_status"`
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
	FilteredText string
	Context      string
	DocumentId   string
	EntityCount  int
	EntityTypes  []string
	Latency      time.Duration
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

func getBoolEnv(key string, defaultVal bool) bool {
	val, exists := os.LookupEnv(key)
	if !exists {
		return defaultVal
	}
	return strings.EqualFold(val, "true") || val == "1"
}

func Filter(client *http.Client, endpoint string, input string, context string, documentId string, policyName string) FilterResponse {

	var text = []byte(input)

	base, err := url.Parse(endpoint + "/api/explain")

	if err != nil {
		slog.Error("Failed to parse Philter endpoint", "error", err)
		os.Exit(1)
	}

	params := url.Values{}
	params.Add("c", context)
	params.Add("d", documentId)
	params.Add("p", policyName)

	base.RawQuery = params.Encode()

	request, err := http.NewRequest("POST", base.String(), bytes.NewReader(text))

	if err != nil {
		slog.Error("Failed to create Philter request", "error", err)
		os.Exit(1)
	}

	request.Header.Add("Content-Type", "text/plain")

	start := time.Now()
	response, err := client.Do(request)
	latency := time.Since(start)

	responseData, err := ioutil.ReadAll(response.Body)

	if err != nil {
		slog.Error("Failed to read Philter response", "error", err)
		os.Exit(1)
	}

	response.Body.Close()

	var explainResp ExplainResponse
	if err := json.Unmarshal(responseData, &explainResp); err != nil {
		slog.Error("Failed to parse Philter explain response", "error", err)
		os.Exit(1)
	}

	typesSet := make(map[string]struct{})
	for _, span := range explainResp.Explanation.AppliedSpans {
		typesSet[span.FilterType] = struct{}{}
	}
	entityTypes := make([]string, 0, len(typesSet))
	for t := range typesSet {
		entityTypes = append(entityTypes, t)
	}

	return FilterResponse{
		FilteredText: explainResp.FilteredText,
		Context:      explainResp.Context,
		DocumentId:   explainResp.DocumentId,
		EntityCount:  len(explainResp.Explanation.AppliedSpans),
		EntityTypes:  entityTypes,
		Latency:      latency,
	}

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
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		return
	}

	philter_endpoint := getEnv("PHILTER_ENDPOINT", "https://localhost:8080")
	philter_context := getEnv("PHILTER_CONTEXT", "none")
	philter_document_id := os.Getenv("PHILTER_DOCUMENT_ID")
	if philter_document_id == "" {
		philter_document_id = uuid.New().String()
	}
	philter_policy_name := getEnv("PHILTER_POLICY_NAME", "default")

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
		p.handleAnthropic(rc, r, philter_endpoint, philter_context, philter_document_id, philter_policy_name, audit)
	} else if strings.Contains(r.URL.Path, ":generateContent") {
		audit.Provider = "gemini"
		p.handleGeminiNative(rc, r, philter_endpoint, philter_context, philter_document_id, philter_policy_name, audit)
	} else if r.URL.Path == "/api/generate" {
		audit.Provider = "ollama"
		p.handleOllamaGenerate(rc, r, philter_endpoint, philter_context, philter_document_id, philter_policy_name, audit)
	} else if r.URL.Path == "/api/chat" {
		audit.Provider = "ollama"
		p.handleOllamaChat(rc, r, philter_endpoint, philter_context, philter_document_id, philter_policy_name, audit)
	} else {
		audit.Provider = "openai"
		p.handleOpenAI(rc, r, philter_endpoint, philter_context, philter_document_id, philter_policy_name, audit)
	}

	audit.HTTPStatus = rc.statusCode
	emitAuditLog(p.auditLogger, *audit)
}

func (p *Proxy) handleOllamaGenerate(w http.ResponseWriter, r *http.Request, philter_endpoint string, context string, documentId string, policyName string, audit *AuditEntry) {
	var o OllamaGenerateRequest
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(bodyBytes, &o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.Model = o.Model

	if o.Prompt != "" {
		filterResponse := Filter(p.philterClient, philter_endpoint, o.Prompt, context, documentId, policyName)
		o.Prompt = filterResponse.FilteredText
		audit.recordFilterResult(filterResponse)
	}

	if o.System != "" {
		filterResponse := Filter(p.philterClient, philter_endpoint, o.System, context, documentId, policyName)
		o.System = filterResponse.FilteredText
		audit.recordFilterResult(filterResponse)
	}

	j, err := json.Marshal(o)
	new_body_content := string(j[:])

	r.Body = ioutil.NopCloser(strings.NewReader(new_body_content))
	r.ContentLength = int64(len(new_body_content))
	r.Host = p.ollamaTarget.Host

	p.ollamaProxy.ServeHTTP(w, r)
}

func (p *Proxy) handleOllamaChat(w http.ResponseWriter, r *http.Request, philter_endpoint string, context string, documentId string, policyName string, audit *AuditEntry) {
	var o OllamaChatRequest
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(bodyBytes, &o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.Model = o.Model

	for i := 0; i < len(o.Messages); i++ {
		filterResponse := Filter(p.philterClient, philter_endpoint, o.Messages[i].Content, context, documentId, policyName)
		o.Messages[i].Content = filterResponse.FilteredText
		audit.recordFilterResult(filterResponse)
	}

	j, err := json.Marshal(o)
	new_body_content := string(j[:])

	r.Body = ioutil.NopCloser(strings.NewReader(new_body_content))
	r.ContentLength = int64(len(new_body_content))
	r.Host = p.ollamaTarget.Host

	p.ollamaProxy.ServeHTTP(w, r)
}

func (p *Proxy) handleGeminiNative(w http.ResponseWriter, r *http.Request, philter_endpoint string, context string, documentId string, policyName string, audit *AuditEntry) {
	var g GeminiRequest
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(bodyBytes, &g)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for i := 0; i < len(g.Contents); i++ {
		for j := 0; j < len(g.Contents[i].Parts); j++ {
			if g.Contents[i].Parts[j].Text != "" {
				filterResponse := Filter(p.philterClient, philter_endpoint, g.Contents[i].Parts[j].Text, context, documentId, policyName)
				g.Contents[i].Parts[j].Text = filterResponse.FilteredText
				audit.recordFilterResult(filterResponse)
			}
		}
	}

	j, err := json.Marshal(g)
	new_body_content := string(j[:])

	r.Body = ioutil.NopCloser(strings.NewReader(new_body_content))
	r.ContentLength = int64(len(new_body_content))
	r.Host = p.geminiTarget.Host

	p.geminiProxy.ServeHTTP(w, r)
}

func (p *Proxy) handleOpenAI(w http.ResponseWriter, r *http.Request, philter_endpoint string, context string, documentId string, policyName string, audit *AuditEntry) {
	var o OpenAIRequest
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(bodyBytes, &o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.Model = o.Model

	for i := 0; i < len(o.Messages); i++ {
		filterResponse := Filter(p.philterClient, philter_endpoint, o.Messages[i].Content, context, documentId, policyName)
		o.Messages[i].Content = filterResponse.FilteredText
		audit.recordFilterResult(filterResponse)
	}

	j, err := json.Marshal(o)
	new_body_content := string(j[:])

	r.Body = ioutil.NopCloser(strings.NewReader(new_body_content))
	r.ContentLength = int64(len(new_body_content))
	r.Host = p.openaiTarget.Host

	p.openaiProxy.ServeHTTP(w, r)
}

func (p *Proxy) handleAnthropic(w http.ResponseWriter, r *http.Request, philter_endpoint string, context string, documentId string, policyName string, audit *AuditEntry) {
	var a AnthropicRequest
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(bodyBytes, &a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit.Model = a.Model

	if a.System != "" {
		filterResponse := Filter(p.philterClient, philter_endpoint, a.System, context, documentId, policyName)
		a.System = filterResponse.FilteredText
		audit.recordFilterResult(filterResponse)
	}

	for i := 0; i < len(a.Messages); i++ {
		switch v := a.Messages[i].Content.(type) {
		case string:
			filterResponse := Filter(p.philterClient, philter_endpoint, v, context, documentId, policyName)
			a.Messages[i].Content = filterResponse.FilteredText
			audit.recordFilterResult(filterResponse)
		case []any:
			for j := 0; j < len(v); j++ {
				if block, ok := v[j].(map[string]any); ok {
					if block["type"] == "text" {
						if text, ok := block["text"].(string); ok {
							filterResponse := Filter(p.philterClient, philter_endpoint, text, context, documentId, policyName)
							block["text"] = filterResponse.FilteredText
							audit.recordFilterResult(filterResponse)
						}
					}
				}
			}
		}
	}

	j, err := json.Marshal(a)
	new_body_content := string(j[:])

	r.Body = ioutil.NopCloser(strings.NewReader(new_body_content))
	r.ContentLength = int64(len(new_body_content))
	r.Host = p.anthropicTarget.Host

	p.anthropicProxy.ServeHTTP(w, r)
}

func getEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
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

	loggingEnabled := getBoolEnv("PHILTER_LOGGING_ENABLED", true)
	logFile := getEnv("PHILTER_LOG_FILE", "")
	auditLogger := setupAuditLogger(loggingEnabled, logFile)

	philterTLSVerify := getBoolEnv("PHILTER_TLS_VERIFY", true)
	philterCACert := getEnv("PHILTER_CA_CERT", "")
	providerTLSVerify := getBoolEnv("PROVIDER_TLS_VERIFY", true)

	philterTLSConfig, err := buildTLSConfig(!philterTLSVerify, philterCACert)
	if err != nil {
		slog.Error("Philter TLS configuration error", "error", err)
		os.Exit(1)
	}
	providerTLSConfig, err := buildTLSConfig(!providerTLSVerify, "")
	if err != nil {
		slog.Error("Provider TLS configuration error", "error", err)
		os.Exit(1)
	}

	philterClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: philterTLSConfig,
		},
	}

	openaiTarget, err := url.Parse("https://api.openai.com")
	if err != nil {
		panic(err)
	}

	anthropicTarget, err := url.Parse("https://api.anthropic.com")
	if err != nil {
		panic(err)
	}

	geminiTarget, err := url.Parse("https://generativelanguage.googleapis.com")
	if err != nil {
		panic(err)
	}

	ollamaTarget, err := url.Parse(getEnv("OLLAMA_HOST", "http://localhost:11434"))
	if err != nil {
		panic(err)
	}

	openaiProxy := httputil.NewSingleHostReverseProxy(openaiTarget)
	openaiProxy.Transport = &http.Transport{
		TLSClientConfig: providerTLSConfig,
	}

	anthropicProxy := httputil.NewSingleHostReverseProxy(anthropicTarget)
	anthropicProxy.Transport = &http.Transport{
		TLSClientConfig: providerTLSConfig,
	}

	geminiProxy := httputil.NewSingleHostReverseProxy(geminiTarget)
	geminiProxy.Transport = &http.Transport{
		TLSClientConfig: providerTLSConfig,
	}

	ollamaProxy := httputil.NewSingleHostReverseProxy(ollamaTarget)
	ollamaProxy.Transport = &http.Transport{
		TLSClientConfig: providerTLSConfig,
	}

	p := &Proxy{
		openaiTarget:    openaiTarget,
		anthropicTarget: anthropicTarget,
		geminiTarget:    geminiTarget,
		ollamaTarget:    ollamaTarget,
		openaiProxy:     openaiProxy,
		anthropicProxy:  anthropicProxy,
		geminiProxy:     geminiProxy,
		ollamaProxy:     ollamaProxy,
		philterClient:   philterClient,
		auditLogger:     auditLogger,
	}

	port := getEnv("PHILTER_PROXY_PORT", "8080")
	cert_file := getEnv("PHILTER_PROXY_CERT_FILE", "cert.pem")
	key_file := getEnv("PHILTER_PROXY_KEY_FILE", "key.pem")
	shutdownTimeoutSec, _ := strconv.Atoi(getEnv("PHILTER_SHUTDOWN_TIMEOUT", "30"))

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: p,
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

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Forced shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Shutdown complete")
}
