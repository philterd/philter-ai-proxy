package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func testConfig(philterEndpoint string) *Config {
	cfg := defaultConfig()
	cfg.Philter.Retry = RetryConfig{MaxAttempts: 1}
	cfg.Philter.CircuitBreaker = CircuitBreakerConfig{Enabled: false}
	if philterEndpoint != "" {
		cfg.Philter.Endpoint = philterEndpoint
	}
	return cfg
}

func testPhilterClient(url string) *PhilterClient {
	return newPhilterClient(http.DefaultClient, url,
		RetryConfig{MaxAttempts: 1},
		CircuitBreakerConfig{Enabled: false},
	)
}

// testKeyStore builds a keyStore from a (rawKey -> boundPolicy) map. Mirrors
// the shape the old test code used to assign to Proxy.keyIndex; useful when
// the test does not depend on per-entry key IDs.
func testKeyStore(m map[string]string) *keyStore {
	entries := make([]APIKeyEntry, 0, len(m))
	for k, p := range m {
		entries = append(entries, APIKeyEntry{Key: k, Policy: p})
	}
	ks, _ := newKeyStore(entries)
	return ks
}

func testFilterFunc(url string) filterFunc {
	return func(_ context.Context, input, philterCtx, docID, policy string) (FilterResponse, error) {
		return Filter(http.DefaultClient, url, input, philterCtx, docID, policy)
	}
}

func TestBuildTLSConfig_VerifyEnabled(t *testing.T) {
	config, err := buildTLSConfig(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if config.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be false")
	}
	if config.RootCAs != nil {
		t.Error("Expected RootCAs to be nil when no CA cert provided")
	}
}

func TestBuildTLSConfig_VerifyDisabled(t *testing.T) {
	config, err := buildTLSConfig(true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !config.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be true")
	}
}

func generateTestCACert(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	tmpFile, err := os.CreateTemp("", "test-ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(tmpFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tmpFile.Close()
	return tmpFile.Name()
}

func TestBuildTLSConfig_CustomCA(t *testing.T) {
	caFile := generateTestCACert(t)
	defer os.Remove(caFile)

	config, err := buildTLSConfig(false, caFile)
	if err != nil {
		t.Fatal(err)
	}
	if config.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be false")
	}
	if config.RootCAs == nil {
		t.Error("Expected RootCAs to be set when CA cert provided")
	}
}

func TestBuildTLSConfig_CustomCA_SkippedWhenInsecure(t *testing.T) {
	config, err := buildTLSConfig(true, "/nonexistent/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !config.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be true")
	}
	if config.RootCAs != nil {
		t.Error("Expected RootCAs to be nil when InsecureSkipVerify is true")
	}
}

func TestBuildTLSConfig_InvalidCAPath(t *testing.T) {
	_, err := buildTLSConfig(false, "/nonexistent/ca.pem")
	if err == nil {
		t.Error("Expected error for nonexistent CA file")
	}
}

func TestBuildTLSConfig_InvalidCAPEM(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "bad-ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("not a valid PEM certificate")
	tmpFile.Close()

	_, err = buildTLSConfig(false, tmpFile.Name())
	if err == nil {
		t.Error("Expected error for invalid PEM content")
	}
}

func explainJSON(filteredText, docID string, spans []Span) []byte {
	resp := ExplainResponse{
		FilteredText: filteredText,
		Context:      "none",
		DocumentId:   docID,
		Explanation:  Explanation{AppliedSpans: spans},
	}
	b, _ := json.Marshal(resp)
	return b
}

func TestFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/explain" {
			t.Errorf("Expected path /api/explain, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		q := r.URL.Query()
		if q.Get("c") != "context" || q.Get("d") != "docid" || q.Get("p") != "policy" {
			t.Errorf("Query parameters mismatch: %v", q)
		}

		w.Write(explainJSON("filtered text", "test-doc-id", []Span{
			{FilterType: "NER_ENTITY", Confidence: 0.95},
		}))
	}))
	defer server.Close()

	resp, err := Filter(http.DefaultClient, server.URL, "original text", "context", "docid", "policy")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resp.FilteredText != "filtered text" {
		t.Errorf("Expected 'filtered text', got '%s'", resp.FilteredText)
	}
	if resp.DocumentId != "test-doc-id" {
		t.Errorf("Expected 'test-doc-id', got '%s'", resp.DocumentId)
	}
	if resp.EntityCount != 1 {
		t.Errorf("Expected EntityCount 1, got %d", resp.EntityCount)
	}
	if len(resp.EntityTypes) != 1 || resp.EntityTypes[0] != "NER_ENTITY" {
		t.Errorf("Expected EntityTypes [NER_ENTITY], got %v", resp.EntityTypes)
	}
	if resp.EntityTypeCounts["NER_ENTITY"] != 1 {
		t.Errorf("Expected EntityTypeCounts[NER_ENTITY]=1, got %d", resp.EntityTypeCounts["NER_ENTITY"])
	}
}

func TestFilter_Error(t *testing.T) {
	_, err := Filter(http.DefaultClient, "http://127.0.0.1:1", "text", "ctx", "doc", "policy")
	if err == nil {
		t.Error("Expected error when Philter is unreachable")
	}
}

func TestProxy_ServeHTTP_CustomConfig(t *testing.T) {
	// Mock Philter
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("c") != "custom-context" {
			t.Errorf("Expected context 'custom-context', got '%s'", q.Get("c"))
		}
		if q.Get("p") != "custom-policy" {
			t.Errorf("Expected policy 'custom-policy', got '%s'", q.Get("p"))
		}
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()

	// Mock OpenAI
	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OpenAIRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)
		var content string
		json.Unmarshal(req.Messages[0].Content, &content)
		if content != "REDACTED" {
			t.Errorf("Expected 'REDACTED', got '%s'", content)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	cfg := testConfig(philterServer.URL)
	cfg.Defaults.Policy = "custom-policy"
	cfg.Defaults.Context = "custom-context"

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:       cfg,
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(cfg.Philter.Endpoint),
	}

	reqBody := `{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "secret"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_RandomUUID(t *testing.T) {
	// Mock Philter
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		docId := q.Get("d")
		if docId == "" {
			t.Errorf("Expected non-empty document ID (random UUID)")
		}
		// Basic check if it looks like a UUID (length check)
		if len(docId) != 36 {
			t.Errorf("Expected UUID of length 36, got '%s' (length %d)", docId, len(docId))
		}
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()

	// Mock OpenAI
	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterServer.URL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(philterServer.URL),
	}

	reqBody := `{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "secret"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_OpenAI(t *testing.T) {
	// Mock Philter
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		log.Printf("Philter received: %s", string(body))
		if string(body) == "John Smith" || string(body) == "Hello John Smith" {
			w.Write(explainJSON("Hello REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		} else {
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	// Mock OpenAI
	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OpenAIRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)
		var content string
		json.Unmarshal(req.Messages[0].Content, &content)
		if content != "Hello REDACTED" {
			t.Errorf("Expected 'Hello REDACTED', got '%s'", content)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": "chatcmpl-123"}`))
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	// Re-initialize proxy correctly for testing
	proxy := &Proxy{
		config:       testConfig(philterURL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(philterURL),
	}

	reqBody := `{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello John Smith"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_Anthropic(t *testing.T) {
	// Mock Philter
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		log.Printf("Philter received: %s", string(body))
		if string(body) == "John Smith" || string(body) == "Hello John Smith" {
			w.Write(explainJSON("Hello REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		} else {
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	// Mock Anthropic
	anthropicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AnthropicRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)

		content := req.Messages[0].Content.(string)
		if content != "Hello REDACTED" {
			t.Errorf("Expected 'Hello REDACTED', got '%s'", content)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": "msg_123"}`))
	}))
	defer anthropicServer.Close()

	anthropicURL, _ := url.Parse(anthropicServer.URL)
	proxy := &Proxy{
		config:          testConfig(philterURL),
		anthropicTarget: anthropicURL,
		anthropicClient: http.DefaultClient,
		philter:         testPhilterClient(philterURL),
	}

	reqBody := `{"model": "claude-3-opus", "messages": [{"role": "user", "content": "Hello John Smith"}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_Anthropic_Complex(t *testing.T) {
	// Mock Philter
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) == "Hello John Smith" {
			w.Write(explainJSON("Hello REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		} else {
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	// Mock Anthropic
	anthropicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AnthropicRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)

		blocks := req.Messages[0].Content.([]any)
		text := blocks[0].(map[string]any)["text"].(string)

		if text != "Hello REDACTED" {
			t.Errorf("Expected 'Hello REDACTED', got '%s'", text)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": "msg_123"}`))
	}))
	defer anthropicServer.Close()

	anthropicURL, _ := url.Parse(anthropicServer.URL)
	proxy := &Proxy{
		config:          testConfig(philterURL),
		anthropicTarget: anthropicURL,
		anthropicClient: http.DefaultClient,
		philter:         testPhilterClient(philterURL),
	}

	reqBody := `{"model": "claude-3-opus", "messages": [{"role": "user", "content": [{"type": "text", "text": "Hello John Smith"}]}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_Anthropic_System(t *testing.T) {
	// Mock Philter
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) == "Hello John Smith" {
			w.Write(explainJSON("Hello REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		} else {
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	// Mock Anthropic
	anthropicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AnthropicRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)

		if req.System != "Hello REDACTED" {
			t.Errorf("Expected system 'Hello REDACTED', got '%s'", req.System)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": "msg_123"}`))
	}))
	defer anthropicServer.Close()

	anthropicURL, _ := url.Parse(anthropicServer.URL)
	proxy := &Proxy{
		config:          testConfig(philterURL),
		anthropicTarget: anthropicURL,
		anthropicClient: http.DefaultClient,
		philter:         testPhilterClient(philterURL),
	}

	reqBody := `{"model": "claude-3-opus", "system": "Hello John Smith", "messages": [{"role": "user", "content": "Hi"}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_Gemini(t *testing.T) {
	// Mock Philter
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) == "John Smith" {
			w.Write(explainJSON("REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		} else {
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	// Mock Gemini
	geminiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req GeminiRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)

		text := req.Contents[0].Parts[0].Text
		if text != "REDACTED" {
			t.Errorf("Expected 'REDACTED', got '%s'", text)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"candidates": [{"content": {"parts": [{"text": "Hello!"}]}}]}`))
	}))
	defer geminiServer.Close()

	geminiURL, _ := url.Parse(geminiServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterURL),
		geminiTarget: geminiURL,
		geminiClient: http.DefaultClient,
		philter:      testPhilterClient(philterURL),
	}

	reqBody := `{"contents": [{"parts": [{"text": "John Smith"}]}]}`
	req := httptest.NewRequest("POST", "/v1beta/models/gemini-pro:generateContent", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_Health(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer philterServer.Close()

	proxy := &Proxy{
		config:  testConfig(philterServer.URL),
		philter: testPhilterClient(philterServer.URL),
	}
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("Expected ok status in body, got %s", body)
	}
}

func TestProxy_ServeHTTP_Health_Degraded(t *testing.T) {
	proxy := &Proxy{
		config:  testConfig("http://127.0.0.1:1"),
		philter: testPhilterClient("http://127.0.0.1:1"),
	}
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"status":"degraded"`) {
		t.Errorf("Expected degraded status in body, got %s", body)
	}
}

func TestProxy_ServeHTTP_Health_NilConfig(t *testing.T) {
	proxy := &Proxy{}
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_OllamaGenerate(t *testing.T) {
	// Mock Philter
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) == "John Smith" {
			w.Write(explainJSON("REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		} else {
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	// Mock Ollama
	ollamaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OllamaGenerateRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)

		if req.Prompt != "REDACTED" {
			t.Errorf("Expected prompt 'REDACTED', got '%s'", req.Prompt)
		}
		if req.System != "REDACTED" {
			t.Errorf("Expected system 'REDACTED', got '%s'", req.System)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"model": "llama3", "response": "Hello!"}`))
	}))
	defer ollamaServer.Close()

	ollamaURL, _ := url.Parse(ollamaServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterURL),
		ollamaTarget: ollamaURL,
		ollamaClient: http.DefaultClient,
		philter:      testPhilterClient(philterURL),
	}

	reqBody := `{"model": "llama3", "prompt": "John Smith", "system": "John Smith"}`
	req := httptest.NewRequest("POST", "/api/generate", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_OllamaChat(t *testing.T) {
	// Mock Philter
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) == "John Smith" {
			w.Write(explainJSON("REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		} else {
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	// Mock Ollama
	ollamaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OllamaChatRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)

		if req.Messages[0].Content != "REDACTED" {
			t.Errorf("Expected message content 'REDACTED', got '%s'", req.Messages[0].Content)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"model": "llama3", "message": {"role": "assistant", "content": "Hello!"}}`))
	}))
	defer ollamaServer.Close()

	ollamaURL, _ := url.Parse(ollamaServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterURL),
		ollamaTarget: ollamaURL,
		ollamaClient: http.DefaultClient,
		philter:      testPhilterClient(philterURL),
	}

	reqBody := `{"model": "llama3", "messages": [{"role": "user", "content": "John Smith"}]}`
	req := httptest.NewRequest("POST", "/api/chat", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestStreaming_OpenAI_SSE(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	chunks := []string{
		"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n",
		"data: [DONE]\n\n",
	}

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, chunk := range chunks {
			w.Write([]byte(chunk))
			flusher.Flush()
		}
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterURL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(philterURL),
	}

	reqBody := `{"model": "gpt-4", "messages": [{"role": "user", "content": "secret"}], "stream": true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Expected Content-Type text/event-stream, got %s", ct)
	}

	body := w.Body.String()
	expected := strings.Join(chunks, "")
	if body != expected {
		t.Errorf("Expected SSE body:\n%s\nGot:\n%s", expected, body)
	}
}

func TestStreaming_Anthropic_SSE(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	chunks := []string{
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}

	anthropicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, chunk := range chunks {
			w.Write([]byte(chunk))
			flusher.Flush()
		}
	}))
	defer anthropicServer.Close()

	anthropicURL, _ := url.Parse(anthropicServer.URL)
	proxy := &Proxy{
		config:          testConfig(philterURL),
		anthropicTarget: anthropicURL,
		anthropicClient: http.DefaultClient,
		philter:         testPhilterClient(philterURL),
	}

	reqBody := `{"model": "claude-3-opus", "messages": [{"role": "user", "content": "secret"}], "stream": true}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	expected := strings.Join(chunks, "")
	if body != expected {
		t.Errorf("Expected SSE body:\n%s\nGot:\n%s", expected, body)
	}
}

func TestStreaming_Gemini_Chunked(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	chunks := []string{
		"[{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello\"}]}}]}\n",
		",{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" world\"}]}}]}\n",
		"]",
	}

	geminiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, chunk := range chunks {
			w.Write([]byte(chunk))
			flusher.Flush()
		}
	}))
	defer geminiServer.Close()

	geminiURL, _ := url.Parse(geminiServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterURL),
		geminiTarget: geminiURL,
		geminiClient: http.DefaultClient,
		philter:      testPhilterClient(philterURL),
	}

	reqBody := `{"contents": [{"parts": [{"text": "secret"}]}]}`
	req := httptest.NewRequest("POST", "/v1beta/models/gemini-pro:streamGenerateContent", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	expected := strings.Join(chunks, "")
	if body != expected {
		t.Errorf("Expected chunked JSON body:\n%s\nGot:\n%s", expected, body)
	}
}

func TestStreaming_Ollama_NDJSON(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	chunks := []string{
		"{\"model\":\"llama3\",\"response\":\"Hello\"}\n",
		"{\"model\":\"llama3\",\"response\":\" world\"}\n",
		"{\"model\":\"llama3\",\"response\":\"\",\"done\":true}\n",
	}

	ollamaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, chunk := range chunks {
			w.Write([]byte(chunk))
			flusher.Flush()
		}
	}))
	defer ollamaServer.Close()

	ollamaURL, _ := url.Parse(ollamaServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterURL),
		ollamaTarget: ollamaURL,
		ollamaClient: http.DefaultClient,
		philter:      testPhilterClient(philterURL),
	}

	reqBody := `{"model": "llama3", "messages": [{"role": "user", "content": "secret"}]}`
	req := httptest.NewRequest("POST", "/api/chat", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	expected := strings.Join(chunks, "")
	if body != expected {
		t.Errorf("Expected NDJSON body:\n%s\nGot:\n%s", expected, body)
	}
}

func TestStreaming_HeadersPreserved(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("Expected Authorization header, got '%s'", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		// X-Provider-Trace-Id stands in for a generic upstream header. We
		// don't use X-Request-Id here because the proxy owns that header
		// for its own request_id (see error.request_id contract).
		w.Header().Set("X-Provider-Trace-Id", "trace-abc")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data: {}\n\n"))
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterURL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(philterURL),
	}

	reqBody := `{"model": "gpt-4", "messages": [{"role": "user", "content": "secret"}], "stream": true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if got := w.Header().Get("X-Provider-Trace-Id"); got != "trace-abc" {
		t.Errorf("Expected upstream header forwarded, got %q", got)
	}
}

func TestEmitAuditLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	entry := AuditEntry{
		RequestID:      "req-123",
		Direction:      "inbound",
		Provider:       "openai",
		Model:          "gpt-4",
		PolicyName:     "default",
		DocumentID:     "doc-456",
		FieldsRedacted: 2,
		EntityCount:    3,
		EntityTypes:    []string{"NER_ENTITY", "SSN"},
		RedactLatency:  150 * time.Millisecond,
		ClientIP:       "10.0.0.1",
		HTTPStatus:     200,
	}

	emitAuditLog(logger, entry)

	output := buf.String()
	if output == "" {
		t.Fatal("Expected audit log output, got empty string")
	}

	var logEntry map[string]any
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Audit log is not valid JSON: %v", err)
	}

	checks := map[string]any{
		"request_id":        "req-123",
		"direction":         "inbound",
		"provider":          "openai",
		"model":             "gpt-4",
		"policy_name":       "default",
		"document_id":       "doc-456",
		"fields_redacted":   float64(2),
		"entity_count":      float64(3),
		"redact_latency_ms": float64(150),
		"client_ip":         "10.0.0.1",
		"http_status":       float64(200),
	}
	for key, expected := range checks {
		if logEntry[key] != expected {
			t.Errorf("Expected %s=%v, got %v", key, expected, logEntry[key])
		}
	}

	entityTypes, ok := logEntry["entity_types"].([]any)
	if !ok || len(entityTypes) != 2 {
		t.Fatalf("Expected entity_types with 2 items, got %v", logEntry["entity_types"])
	}
	if entityTypes[0] != "NER_ENTITY" || entityTypes[1] != "SSN" {
		t.Errorf("Expected entity_types [NER_ENTITY, SSN], got %v", entityTypes)
	}
}

func TestEmitAuditLog_NilLogger(t *testing.T) {
	emitAuditLog(nil, AuditEntry{})
}

func TestSetupAuditLogger_Enabled(t *testing.T) {
	logger := setupAuditLogger(true, "")
	if logger == nil {
		t.Error("Expected non-nil logger when enabled")
	}
}

func TestSetupAuditLogger_Disabled(t *testing.T) {
	logger := setupAuditLogger(false, "")
	if logger != nil {
		t.Error("Expected nil logger when disabled")
	}
}

func TestSetupAuditLogger_FileOutput(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "audit-log-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	logger := setupAuditLogger(true, tmpFile.Name())
	if logger == nil {
		t.Fatal("Expected non-nil logger")
	}

	logger.Info("test", "key", "value")

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "\"key\":\"value\"") {
		t.Errorf("Expected log entry in file, got: %s", string(content))
	}
}

func TestAuditLog_OpenAI_Integration(t *testing.T) {
	var buf bytes.Buffer
	auditLogger := slog.New(slog.NewJSONHandler(&buf, nil))

	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "test-doc-id", []Span{{FilterType: "NER_ENTITY"}}))
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterURL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(philterURL),
		auditLogger:  auditLogger,
	}

	reqBody := `{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello John Smith"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	output := buf.String()
	var logEntry map[string]any
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Audit log is not valid JSON: %v\nOutput: %s", err, output)
	}

	if logEntry["direction"] != "inbound" {
		t.Errorf("Expected direction 'inbound', got '%v'", logEntry["direction"])
	}
	if logEntry["provider"] != "openai" {
		t.Errorf("Expected provider 'openai', got '%v'", logEntry["provider"])
	}
	if logEntry["model"] != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%v'", logEntry["model"])
	}
	if logEntry["fields_redacted"] != float64(1) {
		t.Errorf("Expected fields_redacted=1, got %v", logEntry["fields_redacted"])
	}
	if logEntry["document_id"] != "test-doc-id" {
		t.Errorf("Expected document_id 'test-doc-id', got '%v'", logEntry["document_id"])
	}
	if logEntry["client_ip"] != "192.168.1.100" {
		t.Errorf("Expected client_ip '192.168.1.100', got '%v'", logEntry["client_ip"])
	}
	if logEntry["request_id"] == nil || logEntry["request_id"] == "" {
		t.Error("Expected non-empty request_id")
	}
	if logEntry["http_status"] != float64(200) {
		t.Errorf("Expected http_status=200, got %v", logEntry["http_status"])
	}
	if logEntry["entity_count"] != float64(1) {
		t.Errorf("Expected entity_count=1, got %v", logEntry["entity_count"])
	}
	entityTypes, ok := logEntry["entity_types"].([]any)
	if !ok || len(entityTypes) != 1 || entityTypes[0] != "NER_ENTITY" {
		t.Errorf("Expected entity_types=[NER_ENTITY], got %v", logEntry["entity_types"])
	}
}

func TestAuditLog_Disabled(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()
	philterURL := philterServer.URL

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterURL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(philterURL),
		auditLogger:  nil,
	}

	reqBody := `{"model": "gpt-4", "messages": [{"role": "user", "content": "secret"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestClientIP(t *testing.T) {
	p := &Proxy{}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"

	if ip := p.clientIP(r); ip != "10.0.0.1" {
		t.Errorf("Expected '10.0.0.1', got '%s'", ip)
	}

	// X-Forwarded-For is ignored by default (no trustedProxies configured),
	// regardless of header content. This is the safe-by-default behaviour
	// when the proxy is exposed directly to the internet -- clients cannot
	// spoof their source IP via XFF.
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	if ip := p.clientIP(r); ip != "10.0.0.1" {
		t.Errorf("Untrusted XFF must be ignored; got %q", ip)
	}

	// With the peer's CIDR in trustedProxies, the left-most XFF entry wins.
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	p.trustedProxies = []*net.IPNet{cidr}
	if ip := p.clientIP(r); ip != "203.0.113.50" {
		t.Errorf("Trusted peer XFF: got %q, want 203.0.113.50", ip)
	}
}

func TestResponseCapture(t *testing.T) {
	w := httptest.NewRecorder()
	rc := newResponseCapture(w)

	if rc.statusCode != http.StatusOK {
		t.Errorf("Expected default status 200, got %d", rc.statusCode)
	}

	rc.WriteHeader(http.StatusBadGateway)
	if rc.statusCode != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", rc.statusCode)
	}
}

func generateTestTLSCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cf, _ := os.CreateTemp("", "test-cert-*.pem")
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(key)
	kf, _ := os.CreateTemp("", "test-key-*.pem")
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	kf.Close()

	return cf.Name(), kf.Name()
}

func TestGracefulShutdown(t *testing.T) {
	certFile, keyFile := generateTestTLSCert(t)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	requestStarted := make(chan struct{})
	requestCanFinish := make(chan struct{})

	proxy := &Proxy{}

	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			proxy.ServeHTTP(w, r)
			return
		}
		close(requestStarted)
		<-requestCanFinish
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("done"))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != http.ErrServerClosed {
			t.Errorf("unexpected server error: %v", err)
		}
	}()

	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	baseURL := fmt.Sprintf("https://127.0.0.1:%d", port)
	for i := 0; i < 20; i++ {
		resp, err := tlsClient.Get(baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	var wg sync.WaitGroup
	var inflightResp *http.Response
	var inflightErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		inflightResp, inflightErr = tlsClient.Get(baseURL + "/slow")
	}()

	<-requestStarted

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- srv.Shutdown(ctx)
	}()

	close(requestCanFinish)

	wg.Wait()
	if inflightErr != nil {
		t.Fatalf("in-flight request failed: %v", inflightErr)
	}
	defer inflightResp.Body.Close()
	if inflightResp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for in-flight request, got %d", inflightResp.StatusCode)
	}
	body, _ := ioutil.ReadAll(inflightResp.Body)
	if string(body) != "done" {
		t.Errorf("Expected body 'done', got '%s'", string(body))
	}

	if err := <-shutdownDone; err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}

	_, err = tlsClient.Get(baseURL + "/health")
	if err == nil {
		t.Error("Expected error connecting after shutdown, but request succeeded")
	}
}

func TestGracefulShutdown_Timeout(t *testing.T) {
	certFile, keyFile := generateTestTLSCert(t)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	requestStarted := make(chan struct{})

	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		close(requestStarted)
		time.Sleep(10 * time.Second)
		w.WriteHeader(http.StatusOK)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		srv.ListenAndServeTLS(certFile, keyFile)
	}()

	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	baseURL := fmt.Sprintf("https://127.0.0.1:%d", port)
	for i := 0; i < 20; i++ {
		resp, err := tlsClient.Get(baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	go func() {
		tlsClient.Get(baseURL + "/slow")
	}()

	<-requestStarted

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err = srv.Shutdown(ctx)
	if err == nil {
		t.Error("Expected shutdown timeout error, but got nil")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("Expected DeadlineExceeded, got: %v", err)
	}
}

func TestProxy_ServeHTTP_OpenAI_SystemMessage(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) == "You are a helpful assistant. The user is John Smith." {
			w.Write(explainJSON("You are a helpful assistant. The user is REDACTED.", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		} else {
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OpenAIRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)
		var content string
		json.Unmarshal(req.Messages[0].Content, &content)
		if content != "You are a helpful assistant. The user is REDACTED." {
			t.Errorf("Expected system content redacted, got '%s'", content)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterServer.URL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(philterServer.URL),
	}

	reqBody := `{"model":"gpt-4","messages":[{"role":"system","content":"You are a helpful assistant. The user is John Smith."}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_OpenAI_ToolResult(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		if strings.Contains(string(body), "John Smith") {
			w.Write(explainJSON("Customer REDACTED, SSN REDACTED, has a balance of $4,200.", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		} else {
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OpenAIRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)
		var content string
		json.Unmarshal(req.Messages[0].Content, &content)
		if !strings.Contains(content, "REDACTED") {
			t.Errorf("Expected tool result content redacted, got '%s'", content)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterServer.URL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(philterServer.URL),
	}

	reqBody := `{"model":"gpt-4","messages":[{"role":"tool","tool_call_id":"call_abc123","content":"Customer John Smith, SSN 123-45-6789, has a balance of $4,200."}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_OpenAI_ToolCallArguments(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		switch string(body) {
		case "John Smith", "123-45-6789":
			w.Write(explainJSON("REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		default:
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OpenAIRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)

		tc := req.Messages[0].ToolCalls[0]
		var args map[string]string
		if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
			t.Errorf("Failed to parse redacted arguments: %v", err)
		}
		if args["name"] != "REDACTED" {
			t.Errorf("Expected name 'REDACTED', got '%s'", args["name"])
		}
		if args["ssn"] != "REDACTED" {
			t.Errorf("Expected ssn 'REDACTED', got '%s'", args["ssn"])
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterServer.URL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(philterServer.URL),
	}

	reqBody := `{"model":"gpt-4","messages":[{"role":"assistant","tool_calls":[{"id":"call_abc123","type":"function","function":{"name":"lookup_customer","arguments":"{\"name\":\"John Smith\",\"ssn\":\"123-45-6789\"}"}}]}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_Anthropic_ToolResult(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		if strings.Contains(string(body), "Margaret Collins") {
			w.Write(explainJSON("Patient REDACTED, DOB REDACTED, MRN REDACTED.", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		} else {
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()

	anthropicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AnthropicRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)

		blocks := req.Messages[0].Content.([]any)
		block := blocks[0].(map[string]any)
		if block["type"] != "tool_result" {
			t.Errorf("Expected type 'tool_result', got '%v'", block["type"])
		}
		content, _ := block["content"].(string)
		if !strings.Contains(content, "REDACTED") {
			t.Errorf("Expected tool_result content redacted, got '%s'", content)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"msg_123"}`))
	}))
	defer anthropicServer.Close()

	anthropicURL, _ := url.Parse(anthropicServer.URL)
	proxy := &Proxy{
		config:          testConfig(philterServer.URL),
		anthropicTarget: anthropicURL,
		anthropicClient: http.DefaultClient,
		philter:         testPhilterClient(philterServer.URL),
	}

	reqBody := `{"model":"claude-3-opus","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_abc123","content":"Patient Margaret Collins, DOB 04/12/1978, MRN 8847291."}]}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestProxy_ServeHTTP_Gemini_FunctionResponse(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		if strings.Contains(string(body), "John Smith") {
			w.Write(explainJSON("Patient REDACTED, SSN REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
		} else {
			w.Write(explainJSON(string(body), "doc-id", nil))
		}
	}))
	defer philterServer.Close()

	geminiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req GeminiRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)

		part := req.Contents[0].Parts[0]
		if part.FunctionResponse == nil {
			t.Fatal("Expected functionResponse part")
		}
		result, _ := part.FunctionResponse.Response["result"].(string)
		if !strings.Contains(result, "REDACTED") {
			t.Errorf("Expected functionResponse result redacted, got '%s'", result)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"candidates":[]}`))
	}))
	defer geminiServer.Close()

	geminiURL, _ := url.Parse(geminiServer.URL)
	proxy := &Proxy{
		config:       testConfig(philterServer.URL),
		geminiTarget: geminiURL,
		geminiClient: http.DefaultClient,
		philter:      testPhilterClient(philterServer.URL),
	}

	reqBody := `{"contents":[{"parts":[{"functionResponse":{"name":"get_patient","response":{"result":"Patient John Smith, SSN 123-45-6789"}}}]}]}`
	req := httptest.NewRequest("POST", "/v1beta/models/gemini-pro:generateContent", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// counterValue reads the current value of a prometheus.Counter.
func counterValue(c prometheus.Counter) float64 {
	m := &dto.Metric{}
	c.Write(m)
	return m.GetCounter().GetValue()
}

// counterVecValue reads the value of a CounterVec for the given label values.
func counterVecValue(cv *prometheus.CounterVec, labels ...string) float64 {
	c, err := cv.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	return counterValue(c)
}

// gaugeValue reads the current value of a prometheus.Gauge.
func gaugeValue(g prometheus.Gauge) float64 {
	m := &dto.Metric{}
	g.Write(m)
	return m.GetGauge().GetValue()
}

func newTestProxy(philterURL, providerURL string, providerKey string) (*Proxy, *ProxyMetrics) {
	reg := prometheus.NewRegistry()
	metrics := newMetrics(reg)
	cfg := testConfig(philterURL)
	u, _ := url.Parse(providerURL)
	p := &Proxy{
		config:  cfg,
		philter: testPhilterClient(cfg.Philter.Endpoint),
		metrics: metrics,
	}
	switch providerKey {
	case "openai":
		p.openaiTarget = u
		p.openaiClient = http.DefaultClient
	case "anthropic":
		p.anthropicTarget = u
		p.anthropicClient = http.DefaultClient
	case "gemini":
		p.geminiTarget = u
		p.geminiClient = http.DefaultClient
	case "ollama":
		p.ollamaTarget = u
		p.ollamaClient = http.DefaultClient
	}
	return p, metrics
}

func TestMetrics_RequestsTotal(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	proxy, m := newTestProxy(philterServer.URL, openaiServer.URL, "openai")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	val := counterVecValue(m.requestsTotal, "openai", "200", "default")
	if val != 1 {
		t.Errorf("Expected requestsTotal=1, got %f", val)
	}
}

func TestMetrics_EntitiesRedacted(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", []Span{
			{FilterType: "NER_ENTITY", Confidence: 0.9},
			{FilterType: "NER_ENTITY", Confidence: 0.85},
			{FilterType: "SSN", Confidence: 0.99},
		}))
	}))
	defer philterServer.Close()

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	proxy, m := newTestProxy(philterServer.URL, openaiServer.URL, "openai")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"John Smith SSN 123-45-6789"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	nerVal := counterVecValue(m.entitiesRedacted, "NER_ENTITY", "openai")
	if nerVal != 2 {
		t.Errorf("Expected NER_ENTITY count=2, got %f", nerVal)
	}
	ssnVal := counterVecValue(m.entitiesRedacted, "SSN", "openai")
	if ssnVal != 1 {
		t.Errorf("Expected SSN count=1, got %f", ssnVal)
	}
}

func TestMetrics_ActiveRequests(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()

	started := make(chan struct{})
	finish := make(chan struct{})
	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-finish
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	proxy, m := newTestProxy(philterServer.URL, openaiServer.URL, "openai")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
		proxy.ServeHTTP(httptest.NewRecorder(), req)
	}()

	<-started
	if v := gaugeValue(m.activeRequests); v != 1 {
		t.Errorf("Expected activeRequests=1 during request, got %f", v)
	}
	close(finish)
	wg.Wait()

	if v := gaugeValue(m.activeRequests); v != 0 {
		t.Errorf("Expected activeRequests=0 after request, got %f", v)
	}
}

func TestMetrics_PhilterError(t *testing.T) {
	proxy, m := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "openai")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
	if v := counterValue(m.philterErrors); v != 1 {
		t.Errorf("Expected philterErrors=1, got %f", v)
	}
}

func TestMetrics_UpstreamError(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()

	proxy, m := newTestProxy(philterServer.URL, "http://127.0.0.1:1", "openai")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
	if v := counterVecValue(m.upstreamErrors, "openai", "502"); v != 1 {
		t.Errorf("Expected upstreamErrors[openai,502]=1, got %f", v)
	}
}

// ── sanitizeQuery ─────────────────────────────────────────────────────────────

func TestSanitizeQuery_SensitiveParams(t *testing.T) {
	cases := []struct {
		input string
		param string
	}{
		{"key=secret&foo=bar", "key"},
		{"token=abc123", "token"},
		{"api_key=sk-xyz", "api_key"},
	}
	for _, tc := range cases {
		out := sanitizeQuery(tc.input)
		if strings.Contains(out, "secret") || strings.Contains(out, "abc123") || strings.Contains(out, "sk-xyz") {
			t.Errorf("sanitizeQuery(%q) did not redact %s: %s", tc.input, tc.param, out)
		}
		if !strings.Contains(out, "REDACTED") {
			t.Errorf("sanitizeQuery(%q) expected REDACTED in output, got: %s", tc.input, out)
		}
	}
}

// sanitizeQuery now operates on an allow-list: any parameter not in the
// known-safe set is redacted regardless of its name. This is intentionally
// stricter than the old deny-list behavior, because the proxy cannot
// statically know which future provider treats which query parameter as a
// credential. The corresponding allow-list test lives next to the rest of
// the security tests as TestSecurity_SanitizeQuery_AllowList.
func TestSanitizeQuery_NonAllowListedParamsRedacted(t *testing.T) {
	out := sanitizeQuery("model=gpt-4&stream=true")
	if !strings.Contains(out, "REDACTED") {
		t.Errorf("non-allow-listed params must be redacted, got: %s", out)
	}
}

func TestSanitizeQuery_InvalidQueryReducesToREDACTED(t *testing.T) {
	out := sanitizeQuery("%z invalid")
	if out != "REDACTED" {
		t.Errorf("unparseable query must reduce to REDACTED, got: %s", out)
	}
}

// ── Filter error paths ────────────────────────────────────────────────────────

func TestFilter_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	_, err := Filter(http.DefaultClient, server.URL, "text", "ctx", "doc", "policy")
	if err == nil {
		t.Error("Expected error when Philter returns invalid JSON")
	}
}

func TestFilter_InvalidEndpoint(t *testing.T) {
	_, err := Filter(http.DefaultClient, "://bad url\x00", "text", "ctx", "doc", "policy")
	if err == nil {
		t.Error("Expected error for invalid endpoint URL")
	}
}

// ── redactAny ─────────────────────────────────────────────────────────────────

func TestRedactAny_EmptyString(t *testing.T) {
	audit := &AuditEntry{}
	result, err := redactAny(context.Background(), testFilterFunc("http://127.0.0.1:1"), "", "ctx", "doc", "pol", audit)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty string, got %v", result)
	}
}

func TestRedactAny_NonStringScalar(t *testing.T) {
	audit := &AuditEntry{}
	for _, v := range []any{42, true, nil, 3.14} {
		result, err := redactAny(context.Background(), testFilterFunc("http://127.0.0.1:1"), v, "ctx", "doc", "pol", audit)
		if err != nil {
			t.Errorf("Unexpected error for %v: %v", v, err)
		}
		if result != v {
			t.Errorf("Expected %v unchanged, got %v", v, result)
		}
	}
}

func TestRedactAny_MapError(t *testing.T) {
	audit := &AuditEntry{}
	m := map[string]any{"name": "John Smith"}
	_, err := redactAny(context.Background(), testFilterFunc("http://127.0.0.1:1"), m, "ctx", "doc", "pol", audit)
	if err == nil {
		t.Error("Expected error when Philter unreachable for map value")
	}
}

func TestRedactAny_SliceError(t *testing.T) {
	audit := &AuditEntry{}
	s := []any{"John Smith", "another value"}
	_, err := redactAny(context.Background(), testFilterFunc("http://127.0.0.1:1"), s, "ctx", "doc", "pol", audit)
	if err == nil {
		t.Error("Expected error when Philter unreachable for slice element")
	}
}

func TestRedactAny_MapSuccess(t *testing.T) {
	philter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc", nil))
	}))
	defer philter.Close()

	audit := &AuditEntry{}
	m := map[string]any{"name": "John", "count": 42}
	result, err := redactAny(context.Background(), testFilterFunc(philter.URL), m, "ctx", "doc", "pol", audit)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	rm := result.(map[string]any)
	if rm["name"] != "REDACTED" {
		t.Errorf("Expected name=REDACTED, got %v", rm["name"])
	}
	if rm["count"] != 42 {
		t.Errorf("Expected count=42 unchanged, got %v", rm["count"])
	}
}

func TestRedactAny_SliceSuccess(t *testing.T) {
	philter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc", nil))
	}))
	defer philter.Close()

	audit := &AuditEntry{}
	s := []any{"John", 99}
	result, err := redactAny(context.Background(), testFilterFunc(philter.URL), s, "ctx", "doc", "pol", audit)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	rs := result.([]any)
	if rs[0] != "REDACTED" {
		t.Errorf("Expected rs[0]=REDACTED, got %v", rs[0])
	}
	if rs[1] != 99 {
		t.Errorf("Expected rs[1]=99 unchanged, got %v", rs[1])
	}
}

// ── redactJSONArguments ───────────────────────────────────────────────────────

func TestRedactJSONArguments_NonJSONString(t *testing.T) {
	philter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc", []Span{{FilterType: "NER_ENTITY"}}))
	}))
	defer philter.Close()

	audit := &AuditEntry{}
	result, err := redactJSONArguments(context.Background(), testFilterFunc(philter.URL), "not json at all", "ctx", "doc", "pol", audit)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "REDACTED" {
		t.Errorf("Expected REDACTED, got %s", result)
	}
}

func TestRedactJSONArguments_NonJSON_PhilterError(t *testing.T) {
	audit := &AuditEntry{}
	_, err := redactJSONArguments(context.Background(), testFilterFunc("http://127.0.0.1:1"), "not json", "ctx", "doc", "pol", audit)
	if err == nil {
		t.Error("Expected error when non-JSON argument and Philter unreachable")
	}
}

func TestRedactJSONArguments_PhilterError(t *testing.T) {
	audit := &AuditEntry{}
	_, err := redactJSONArguments(context.Background(), testFilterFunc("http://127.0.0.1:1"), `{"name":"John"}`, "ctx", "doc", "pol", audit)
	if err == nil {
		t.Error("Expected error when Philter unreachable for JSON argument")
	}
}

// ── bad-JSON request bodies ───────────────────────────────────────────────────

func philterOK() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc", nil))
	}))
}

func TestHandleOpenAI_BadJSON(t *testing.T) {
	ps := philterOK()
	defer ps.Close()
	proxy, _ := newTestProxy(ps.URL, "http://127.0.0.1:1", "openai")
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader("{bad json}"))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandleOpenAI_PhilterError_ContentMessage(t *testing.T) {
	proxy, _ := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "openai")
	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestHandleOpenAI_PhilterError_ToolArgs(t *testing.T) {
	proxy, _ := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "openai")
	reqBody := `{"model":"gpt-4","messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"x\":\"John\"}"}}]}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestHandleOllamaGenerate_BadJSON(t *testing.T) {
	ps := philterOK()
	defer ps.Close()
	proxy, _ := newTestProxy(ps.URL, "http://127.0.0.1:1", "ollama")
	req := httptest.NewRequest("POST", "/api/generate", strings.NewReader("{bad}"))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandleOllamaGenerate_PhilterError_Prompt(t *testing.T) {
	proxy, _ := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "ollama")
	req := httptest.NewRequest("POST", "/api/generate", strings.NewReader(`{"model":"llama3","prompt":"hello"}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestHandleOllamaGenerate_PhilterError_System(t *testing.T) {
	// Prompt succeeds, system fails — use a server that fails after first request
	callCount := 0
	ps := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Write(explainJSON("REDACTED", "doc", nil))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("not json"))
		}
	}))
	defer ps.Close()

	proxy, _ := newTestProxy(ps.URL, "http://127.0.0.1:1", "ollama")
	req := httptest.NewRequest("POST", "/api/generate", strings.NewReader(`{"model":"llama3","prompt":"hello","system":"sys"}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestHandleOllamaChat_BadJSON(t *testing.T) {
	ps := philterOK()
	defer ps.Close()
	proxy, _ := newTestProxy(ps.URL, "http://127.0.0.1:1", "ollama")
	req := httptest.NewRequest("POST", "/api/chat", strings.NewReader("{bad}"))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandleOllamaChat_PhilterError(t *testing.T) {
	proxy, _ := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "ollama")
	req := httptest.NewRequest("POST", "/api/chat", strings.NewReader(`{"model":"llama3","messages":[{"role":"user","content":"hi"}]}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestHandleGemini_BadJSON(t *testing.T) {
	ps := philterOK()
	defer ps.Close()
	proxy, _ := newTestProxy(ps.URL, "http://127.0.0.1:1", "gemini")
	req := httptest.NewRequest("POST", "/v1beta/models/gemini-pro:generateContent", strings.NewReader("{bad}"))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandleGemini_PhilterError_TextPart(t *testing.T) {
	proxy, _ := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "gemini")
	reqBody := `{"contents":[{"parts":[{"text":"hello"}]}]}`
	req := httptest.NewRequest("POST", "/v1beta/models/gemini-pro:generateContent", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestHandleGemini_PhilterError_FunctionResponse(t *testing.T) {
	proxy, _ := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "gemini")
	reqBody := `{"contents":[{"parts":[{"functionResponse":{"name":"f","response":{"result":"John Smith"}}}]}]}`
	req := httptest.NewRequest("POST", "/v1beta/models/gemini-pro:generateContent", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestHandleAnthropic_BadJSON(t *testing.T) {
	ps := philterOK()
	defer ps.Close()
	proxy, _ := newTestProxy(ps.URL, "http://127.0.0.1:1", "anthropic")
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader("{bad}"))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestHandleAnthropic_PhilterError_System(t *testing.T) {
	proxy, _ := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "anthropic")
	reqBody := `{"model":"claude-3-opus","system":"You are helpful","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestHandleAnthropic_PhilterError_StringMessage(t *testing.T) {
	proxy, _ := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "anthropic")
	reqBody := `{"model":"claude-3-opus","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestHandleAnthropic_PhilterError_TextBlock(t *testing.T) {
	proxy, _ := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "anthropic")
	reqBody := `{"model":"claude-3-opus","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestHandleAnthropic_PhilterError_ToolResult(t *testing.T) {
	proxy, _ := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "anthropic")
	reqBody := `{"model":"claude-3-opus","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"John Smith"}]}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestHandleAnthropic_ToolResult_ArrayContent(t *testing.T) {
	ps := philterOK()
	defer ps.Close()

	anthropicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AnthropicRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &req)
		blocks := req.Messages[0].Content.([]any)
		block := blocks[0].(map[string]any)
		inner := block["content"].([]any)
		subBlock := inner[0].(map[string]any)
		if subBlock["text"] != "REDACTED" {
			t.Errorf("Expected nested text=REDACTED, got %v", subBlock["text"])
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"msg_1"}`))
	}))
	defer anthropicServer.Close()

	anthropicURL, _ := url.Parse(anthropicServer.URL)
	proxy := &Proxy{
		config:          testConfig(ps.URL),
		anthropicTarget: anthropicURL,
		anthropicClient: http.DefaultClient,
		philter:         testPhilterClient(ps.URL),
	}

	reqBody := `{"model":"claude-3-opus","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"John Smith"}]}]}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestHandleAnthropic_PhilterError_ToolResult_ArrayContent(t *testing.T) {
	proxy, _ := newTestProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "anthropic")
	reqBody := `{"model":"claude-3-opus","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"John Smith"}]}]}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

// ── forwardToProvider: upstream 4xx/5xx response ──────────────────────────────

func TestForwardToProvider_UpstreamErrorResponse(t *testing.T) {
	ps := philterOK()
	defer ps.Close()

	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer upstreamServer.Close()

	proxy, m := newTestProxy(ps.URL, upstreamServer.URL, "openai")
	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 from upstream, got %d", w.Code)
	}
	if v := counterVecValue(m.upstreamErrors, "openai", "500"); v != 1 {
		t.Errorf("Expected upstreamErrors[openai,500]=1, got %f", v)
	}
}

func TestForwardToProvider_QueryStringInErrorLog(t *testing.T) {
	// Ensures sanitizeQuery is exercised via forwardToProvider's error path
	// when the original request has a query string (e.g. Gemini key param).
	ps := philterOK()
	defer ps.Close()

	proxy := &Proxy{
		config:       testConfig(ps.URL),
		philter:      testPhilterClient(ps.URL),
		geminiTarget: mustParseURL("http://127.0.0.1:1"),
		geminiClient: http.DefaultClient,
	}

	reqBody := `{"contents":[{"parts":[{"text":"hello"}]}]}`
	req := httptest.NewRequest("POST", "/v1beta/models/gemini-pro:generateContent?key=secret", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

// ── config validation ─────────────────────────────────────────────────────────

func TestValidateConfig_InvalidMetricsPort(t *testing.T) {
	cfg := defaultConfig()
	cfg.Metrics.Port = 99999
	if err := validateConfig(cfg); err == nil {
		t.Error("Expected error for out-of-range metrics port")
	}
}

func TestValidateConfig_MetricsDisabled_InvalidPort_OK(t *testing.T) {
	cfg := defaultConfig()
	cfg.Metrics.Enabled = false
	cfg.Metrics.Port = 99999
	if err := validateConfig(cfg); err != nil {
		t.Errorf("Disabled metrics with bad port should not error, got: %v", err)
	}
}

// mustParseURL is a test helper that panics on parse error.
func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// ── outbound scanning ─────────────────────────────────────────────────────────

// newOutboundProxy creates a proxy with a specific provider configured for outbound scanning.
func newOutboundProxy(philterURL, providerURL, provider string, action string) *Proxy {
	return newOutboundProxyCfg(philterURL, providerURL, provider,
		OutboundConfig{Enabled: true, Action: action})
}

// newOutboundProxyCfg exposes the full OutboundConfig for tests needing more
// than `action`.
func newOutboundProxyCfg(philterURL, providerURL, provider string, outbound OutboundConfig) *Proxy {
	cfg := testConfig(philterURL)
	cfg.Defaults.Outbound = outbound
	u, _ := url.Parse(providerURL)
	p := &Proxy{
		config:  cfg,
		philter: testPhilterClient(cfg.Philter.Endpoint),
	}
	switch provider {
	case "openai":
		p.openaiTarget = u
		p.openaiClient = http.DefaultClient
	case "anthropic":
		p.anthropicTarget = u
		p.anthropicClient = http.DefaultClient
	case "gemini":
		p.geminiTarget = u
		p.geminiClient = http.DefaultClient
	case "ollama":
		p.ollamaTarget = u
		p.ollamaClient = http.DefaultClient
	}
	return p
}

// philterRedact returns a Philter mock that redacts the body using the given replacement.
func philterRedact(replacement string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		_ = body
		w.Write(explainJSON(replacement, "doc-out", []Span{{FilterType: "NER_ENTITY", Confidence: 0.9}}))
	}))
}

// philterClean returns a Philter mock that finds no PII.
func philterClean() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		text := string(body)
		w.Write(explainJSON(text, "doc-out", nil))
	}))
}

func TestOutbound_OpenAI_Redact(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Hello John Doe"}}]}`))
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "openai", "redact")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Response is not JSON: %v", err)
	}
	choices := resp["choices"].([]interface{})
	msg := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	if msg["content"] != "[REDACTED]" {
		t.Errorf("Expected redacted content, got %v", msg["content"])
	}
}

func TestOutbound_OpenAI_Block(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"SSN: 123-45-6789"}}]}`))
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "openai", "block")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 when blocking PII, got %d", w.Code)
	}
}

func TestOutbound_OpenAI_Block_NoMatch(t *testing.T) {
	philter := philterClean()
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Hello!"}}]}`))
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "openai", "block")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	// No PII found, so block action passes through
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 (no PII matched), got %d", w.Code)
	}
}

func TestOutbound_OpenAI_Flag(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"SSN: 123-45-6789"}}]}`))
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "openai", "flag")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for flag action, got %d", w.Code)
	}
	// Content should be original (unredacted)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	choices := resp["choices"].([]interface{})
	msg := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	if msg["content"] != "SSN: 123-45-6789" {
		t.Errorf("Expected original content for flag action, got %v", msg["content"])
	}
}

func TestOutbound_Anthropic_Redact(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content":[{"type":"text","text":"Hello John Doe"}],"role":"assistant"}`))
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "anthropic", "redact")

	reqBody := `{"model":"claude-3","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	content := resp["content"].([]interface{})
	block := content[0].(map[string]interface{})
	if block["text"] != "[REDACTED]" {
		t.Errorf("Expected redacted text, got %v", block["text"])
	}
}

func TestOutbound_Gemini_Redact(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"Hello John Doe"}],"role":"model"}}]}`))
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "gemini", "redact")

	reqBody := `{"contents":[{"parts":[{"text":"hi"}]}]}`
	req := httptest.NewRequest("POST", "/v1beta/models/gemini-pro:generateContent", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	candidates := resp["candidates"].([]interface{})
	parts := candidates[0].(map[string]interface{})["content"].(map[string]interface{})["parts"].([]interface{})
	if parts[0].(map[string]interface{})["text"] != "[REDACTED]" {
		t.Errorf("Expected redacted text, got %v", parts[0])
	}
}

func TestOutbound_OllamaGenerate_Redact(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"model":"llama3","response":"Hello John Doe","done":true}`))
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "ollama", "redact")

	reqBody := `{"model":"llama3","prompt":"hi"}`
	req := httptest.NewRequest("POST", "/api/generate", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["response"] != "[REDACTED]" {
		t.Errorf("Expected redacted response, got %v", resp["response"])
	}
}

func TestOutbound_OllamaChat_Redact(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"model":"llama3","message":{"role":"assistant","content":"Hello John Doe"},"done":true}`))
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "ollama", "redact")

	reqBody := `{"model":"llama3","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/api/chat", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	msg := resp["message"].(map[string]interface{})
	if msg["content"] != "[REDACTED]" {
		t.Errorf("Expected redacted content, got %v", msg["content"])
	}
}

func TestOutbound_Streaming_Passthrough(t *testing.T) {
	// When provider returns SSE, outbound scanning is skipped and response passes through.
	philter := philterRedact("[REDACTED]")
	defer philter.Close()

	sseBody := "data: {\"choices\":[{\"delta\":{\"content\":\"John Doe\"}}]}\n\ndata: [DONE]\n\n"
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "openai", "redact")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	// Streaming response passes through unredacted
	if !strings.Contains(w.Body.String(), "John Doe") {
		t.Errorf("Expected streaming body to pass through unmodified, got: %s", w.Body.String())
	}
}

// TestOutboundScan_MalformedResponse_FailsOpen locks down the documented
// fail-open behavior of every outbound response scanner: when a provider
// returns a 2xx body that does not parse as the expected schema, the scanner
// returns the body UNCHANGED, does not block, does not error, and never calls
// Philter. This is a deliberate redaction gap (a broken provider response is
// passed through rather than failing the client's request), so it is asserted
// explicitly across all providers to prevent a silent regression.
func TestOutboundScan_MalformedResponse_FailsOpen(t *testing.T) {
	var philterCalls int32
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&philterCalls, 1)
		w.Write(explainJSON("[REDACTED]", "doc", []Span{{FilterType: "NER_ENTITY", Confidence: 0.9}}))
	}))
	defer philterSrv.Close()

	p := &Proxy{config: testConfig(philterSrv.URL), philter: testPhilterClient(philterSrv.URL)}

	scanners := []struct {
		name string
		scan responseScanner
	}{
		{"openai", p.scanOpenAIResponse},
		{"anthropic", p.scanAnthropicResponse},
		{"gemini", p.scanGeminiResponse},
		{"ollamaGenerate", p.scanOllamaGenerateResponse},
		{"ollamaChat", p.scanOllamaChatResponse},
		{"bedrock", p.scanBedrockResponse},
	}
	// Each body is unparseable as any provider's response schema (syntax error,
	// non-JSON, empty, or a JSON array where an object is required), so every
	// scanner hits its json.Unmarshal-failed early return.
	bodies := []struct {
		name string
		body []byte
	}{
		{"truncated", []byte(`{"choices":[{"message":`)},
		{"not-json", []byte(`<html>502 Bad Gateway</html>`)},
		{"empty", []byte(``)},
		{"json-array", []byte(`[1,2,3]`)},
	}

	for _, s := range scanners {
		for _, b := range bodies {
			t.Run(s.name+"/"+b.name, func(t *testing.T) {
				atomic.StoreInt32(&philterCalls, 0)
				audit := &AuditEntry{}
				out, blocked, err := s.scan(context.Background(), b.body, "ctx", "doc", "", "redact", audit)
				if err != nil {
					t.Fatalf("unparseable body must fail open (no error), got %v", err)
				}
				if blocked {
					t.Errorf("unparseable body must not be blocked")
				}
				if !bytes.Equal(out, b.body) {
					t.Errorf("unparseable body must pass through unchanged: got %q, want %q", out, b.body)
				}
				if n := atomic.LoadInt32(&philterCalls); n != 0 {
					t.Errorf("Philter must not be called for an unparseable response, got %d calls", n)
				}
			})
		}
	}
}

// TestOutbound_Streaming_NotScanned proves the streaming-skip branch directly:
// each case takes a provider response that the non-streaming path WOULD redact,
// and serves it with a streaming Content-Type. Because the response is streamed,
// outbound scanning is skipped, so the PII-bearing text survives verbatim and is
// never replaced with the redaction marker. Covers both text/event-stream and
// application/x-ndjson, across every provider.
func TestOutbound_Streaming_NotScanned(t *testing.T) {
	cases := []struct {
		name        string
		provider    string
		path        string
		reqBody     string
		contentType string
		respBody    string
	}{
		{"openai-sse", "openai", "/v1/chat/completions",
			`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`,
			"text/event-stream",
			`{"choices":[{"message":{"role":"assistant","content":"Hello John Doe"}}]}`},
		{"anthropic-sse", "anthropic", "/v1/messages",
			`{"model":"claude-3","messages":[{"role":"user","content":"hi"}]}`,
			"text/event-stream",
			`{"content":[{"type":"text","text":"Hello John Doe"}],"role":"assistant"}`},
		{"gemini-sse", "gemini", "/v1beta/models/gemini-pro:generateContent",
			`{"contents":[{"parts":[{"text":"hi"}]}]}`,
			"text/event-stream",
			`{"candidates":[{"content":{"parts":[{"text":"Hello John Doe"}],"role":"model"}}]}`},
		{"ollama-ndjson", "ollama", "/api/chat",
			`{"model":"llama3","messages":[{"role":"user","content":"hi"}]}`,
			"application/x-ndjson",
			`{"model":"llama3","message":{"role":"assistant","content":"Hello John Doe"},"done":true}`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			philter := philterRedact("[REDACTED]")
			defer philter.Close()

			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", c.contentType)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(c.respBody))
			}))
			defer provider.Close()

			proxy := newOutboundProxy(philter.URL, provider.URL, c.provider, "redact")
			req := httptest.NewRequest("POST", c.path, strings.NewReader(c.reqBody))
			w := httptest.NewRecorder()
			proxy.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); ct != c.contentType {
				t.Errorf("streaming Content-Type not preserved: got %q, want %q", ct, c.contentType)
			}
			if !strings.Contains(w.Body.String(), "Hello John Doe") {
				t.Errorf("streamed body must pass through un-redacted, got: %s", w.Body.String())
			}
			if strings.Contains(w.Body.String(), "[REDACTED]") {
				t.Errorf("streamed body must NOT be scanned/redacted, got: %s", w.Body.String())
			}
		})
	}
}

// TestOutbound_Streaming_BlockAction_FailsClosed pins the #29 behavior change.
// This previously asserted the opposite: a streamed 200 under `action: block`,
// which any client could trigger with `"stream": true`.
func TestOutbound_Streaming_BlockAction_FailsClosed(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"SSN 123-45-6789"}}]}`))
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "openai", "block")
	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("unscannable stream under block must be rejected; want 403, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "123-45-6789") {
		t.Errorf("unscanned PII must not reach the client, got: %s", w.Body.String())
	}
}

// TestIsStreamingResponse covers the Content-Type classification that gates
// outbound scanning, including the charset-parameter and ndjson cases.
func TestIsStreamingResponse(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"text/event-stream", true},
		{"text/event-stream; charset=utf-8", true},
		{"application/x-ndjson", true},
		{"application/vnd.amazon.eventstream", true},
		{"application/json", false},
		{"application/json; charset=utf-8", false},
		{"", false},
	}
	for _, c := range cases {
		h := http.Header{}
		if c.ct != "" {
			h.Set("Content-Type", c.ct)
		}
		if got := isStreamingResponse(h); got != c.want {
			t.Errorf("isStreamingResponse(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}

func TestOutbound_PhilterError(t *testing.T) {
	// Philter is unreachable during outbound scan — should return 502.
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Hello John"}}]}`))
	}))
	defer provider.Close()

	// Philter responds OK for inbound (first call) then becomes unreachable.
	callCount := 0
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// inbound scan succeeds
			w.Write(explainJSON("hi", "doc", nil))
		} else {
			// outbound scan fails
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("not json"))
		}
	}))
	defer philterServer.Close()

	proxy := newOutboundProxy(philterServer.URL, provider.URL, "openai", "redact")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 on outbound Philter error, got %d", w.Code)
	}
}

func TestOutbound_AuditLog(t *testing.T) {
	var buf bytes.Buffer
	auditLogger := slog.New(slog.NewJSONHandler(&buf, nil))

	philter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("[REDACTED]", "doc-out", []Span{{FilterType: "NER_ENTITY", Confidence: 0.9}}))
	}))
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Hello John"}}]}`))
	}))
	defer provider.Close()

	cfg := testConfig(philter.URL)
	cfg.Defaults.Outbound = OutboundConfig{Enabled: true, Action: "redact"}
	proxy := &Proxy{
		config:       cfg,
		philter:      testPhilterClient(cfg.Philter.Endpoint),
		openaiTarget: mustParseURL(provider.URL),
		openaiClient: http.DefaultClient,
		auditLogger:  auditLogger,
	}

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	// Parse all log lines (inbound + outbound)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("Expected at least 2 audit log lines, got %d: %s", len(lines), buf.String())
	}

	// Find outbound entry
	var outboundEntry map[string]interface{}
	for _, line := range lines {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry["direction"] == "outbound" {
			outboundEntry = entry
			break
		}
	}
	if outboundEntry == nil {
		t.Fatal("No outbound audit log entry found")
	}
	if outboundEntry["provider"] != "openai" {
		t.Errorf("Expected provider 'openai', got %v", outboundEntry["provider"])
	}
	if outboundEntry["http_status"] != float64(200) {
		t.Errorf("Expected http_status=200, got %v", outboundEntry["http_status"])
	}
}

func TestOutbound_Disabled_NoScan(t *testing.T) {
	// When outbound scanning is disabled, response is forwarded as-is.
	philter := philterClean()
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"John Doe"}}]}`))
	}))
	defer provider.Close()

	// Default proxy has outbound disabled
	proxy, _ := newTestProxy(philter.URL, provider.URL, "openai")

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	// Content flows through unmodified
	if !strings.Contains(w.Body.String(), "John Doe") {
		t.Errorf("Expected unredacted content when outbound disabled, got: %s", w.Body.String())
	}
}

// ── config validation (outbound) ──────────────────────────────────────────────

func TestValidateConfig_InvalidOutboundAction(t *testing.T) {
	cfg := defaultConfig()
	cfg.Defaults.Outbound = OutboundConfig{Enabled: true, Action: "invalid"}
	if err := validateConfig(cfg); err == nil {
		t.Error("Expected error for invalid outbound action")
	}
}

func TestValidateConfig_ValidOutboundActions(t *testing.T) {
	for _, action := range []string{"redact", "block", "flag", ""} {
		cfg := defaultConfig()
		cfg.Defaults.Outbound = OutboundConfig{Enabled: true, Action: action}
		if err := validateConfig(cfg); err != nil {
			t.Errorf("Expected no error for action %q, got: %v", action, err)
		}
	}
}

func TestValidateConfig_Route_InvalidOutboundAction(t *testing.T) {
	cfg := defaultConfig()
	cfg.Routes = []RouteConfig{
		{
			Match:    RouteMatch{Header: "x-policy", Value: "hipaa"},
			Policy:   "hipaa",
			Outbound: OutboundConfig{Enabled: true, Action: "badaction"},
		},
	}
	if err := validateConfig(cfg); err == nil {
		t.Error("Expected error for invalid route outbound action")
	}
}

// ── PhilterClient retry ───────────────────────────────────────────────────────

func TestPhilterClient_SuccessOnFirstAttempt(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write(explainJSON("REDACTED", "doc", nil))
	}))
	defer srv.Close()

	pc := newPhilterClient(http.DefaultClient, srv.URL,
		RetryConfig{MaxAttempts: 3, InitialBackoffMs: 1, MaxBackoffMs: 10},
		CircuitBreakerConfig{Enabled: false},
	)
	fr, err := pc.Filter(context.Background(), "hello", "ctx", "doc", "pol")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if fr.FilteredText != "REDACTED" {
		t.Errorf("Expected REDACTED, got %s", fr.FilteredText)
	}
	if calls != 1 {
		t.Errorf("Expected 1 call, got %d", calls)
	}
}

func TestPhilterClient_RetryOnTransientError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 — transient
			return
		}
		w.Write(explainJSON("REDACTED", "doc", nil))
	}))
	defer srv.Close()

	pc := newPhilterClient(http.DefaultClient, srv.URL,
		RetryConfig{MaxAttempts: 3, InitialBackoffMs: 1, MaxBackoffMs: 10},
		CircuitBreakerConfig{Enabled: false},
	)
	fr, err := pc.Filter(context.Background(), "hello", "ctx", "doc", "pol")
	if err != nil {
		t.Fatalf("Expected success after retries, got error: %v", err)
	}
	if fr.FilteredText != "REDACTED" {
		t.Errorf("Expected REDACTED, got %s", fr.FilteredText)
	}
	if calls != 3 {
		t.Errorf("Expected 3 calls, got %d", calls)
	}
}

func TestPhilterClient_NoRetryOn4xx(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest) // 400 — not transient
	}))
	defer srv.Close()

	pc := newPhilterClient(http.DefaultClient, srv.URL,
		RetryConfig{MaxAttempts: 3, InitialBackoffMs: 1, MaxBackoffMs: 10},
		CircuitBreakerConfig{Enabled: false},
	)
	_, err := pc.Filter(context.Background(), "hello", "ctx", "doc", "pol")
	if err == nil {
		t.Error("Expected error for 4xx response")
	}
	if calls != 1 {
		t.Errorf("Expected exactly 1 call (no retry on 4xx), got %d", calls)
	}
}

func TestPhilterClient_ExhaustedRetries(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway) // 502 — transient
	}))
	defer srv.Close()

	pc := newPhilterClient(http.DefaultClient, srv.URL,
		RetryConfig{MaxAttempts: 3, InitialBackoffMs: 1, MaxBackoffMs: 10},
		CircuitBreakerConfig{Enabled: false},
	)
	_, err := pc.Filter(context.Background(), "hello", "ctx", "doc", "pol")
	if err == nil {
		t.Error("Expected error after exhausting retries")
	}
	if calls != 3 {
		t.Errorf("Expected 3 calls (all retried), got %d", calls)
	}
}

// ── Circuit breaker ────────────────────────────────────────────────────────────

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := newCircuitBreaker(3, 30*time.Second, "block")

	for i := 0; i < 3; i++ {
		allowed, _ := cb.allow()
		if !allowed {
			t.Fatalf("Expected allowed before threshold at iteration %d", i)
		}
		cb.recordFailure()
	}

	allowed, fallback := cb.allow()
	if allowed {
		t.Error("Expected circuit breaker to be open after threshold failures")
	}
	if fallback != "block" {
		t.Errorf("Expected fallback=block, got %s", fallback)
	}
	if cb.State() != "open" {
		t.Errorf("Expected state=open, got %s", cb.State())
	}
}

func TestCircuitBreaker_PassthroughFallback(t *testing.T) {
	cb := newCircuitBreaker(1, 30*time.Second, "passthrough")
	cb.allow()
	cb.recordFailure()

	allowed, fallback := cb.allow()
	if allowed {
		t.Error("Expected circuit breaker to block")
	}
	if fallback != "passthrough" {
		t.Errorf("Expected fallback=passthrough, got %s", fallback)
	}
}

func TestCircuitBreaker_HalfOpenAfterTimeout(t *testing.T) {
	cb := newCircuitBreaker(1, 50*time.Millisecond, "block")
	cb.allow()
	cb.recordFailure()

	// Immediately still open
	allowed, _ := cb.allow()
	if allowed {
		t.Error("Expected circuit breaker still open immediately after failure")
	}

	time.Sleep(60 * time.Millisecond)

	// After timeout, should allow probe
	allowed, _ = cb.allow()
	if !allowed {
		t.Error("Expected circuit breaker to allow probe after timeout")
	}
	if cb.State() != "half-open" {
		t.Errorf("Expected state=half-open, got %s", cb.State())
	}
}

func TestCircuitBreaker_ClosesAfterSuccessfulProbe(t *testing.T) {
	cb := newCircuitBreaker(1, 50*time.Millisecond, "block")
	cb.allow()
	cb.recordFailure()
	time.Sleep(60 * time.Millisecond)
	cb.allow() // transitions to half-open

	cb.recordSuccess()
	if cb.State() != "closed" {
		t.Errorf("Expected state=closed after successful probe, got %s", cb.State())
	}
}

func TestCircuitBreaker_ReopensOnProbeFailure(t *testing.T) {
	cb := newCircuitBreaker(1, 50*time.Millisecond, "block")
	cb.allow()
	cb.recordFailure()
	time.Sleep(60 * time.Millisecond)
	cb.allow() // half-open

	cb.recordFailure() // probe fails
	if cb.State() != "open" {
		t.Errorf("Expected state=open after failed probe, got %s", cb.State())
	}
}

func TestPhilterClient_CircuitBreakerBlock(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	pc := newPhilterClient(http.DefaultClient, srv.URL,
		RetryConfig{MaxAttempts: 1, InitialBackoffMs: 1, MaxBackoffMs: 10},
		CircuitBreakerConfig{Enabled: true, Threshold: 2, TimeoutSeconds: 30, Fallback: "block"},
	)

	// Trigger two failures to open the circuit
	pc.Filter(context.Background(), "x", "ctx", "doc", "pol") //nolint
	pc.Filter(context.Background(), "x", "ctx", "doc", "pol") //nolint

	// Circuit should now be open — expect CircuitOpenError
	_, err := pc.Filter(context.Background(), "x", "ctx", "doc", "pol")
	var cbErr *CircuitOpenError
	if !errors.As(err, &cbErr) {
		t.Errorf("Expected CircuitOpenError, got %v", err)
	}
	// Should not have made another HTTP call
	if calls != 2 {
		t.Errorf("Expected 2 HTTP calls (circuit open on 3rd), got %d", calls)
	}
}

func TestPhilterClient_CircuitBreakerPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	pc := newPhilterClient(http.DefaultClient, srv.URL,
		RetryConfig{MaxAttempts: 1, InitialBackoffMs: 1, MaxBackoffMs: 10},
		CircuitBreakerConfig{Enabled: true, Threshold: 1, TimeoutSeconds: 30, Fallback: "passthrough"},
	)

	// Trigger one failure to open the circuit
	pc.Filter(context.Background(), "x", "ctx", "doc", "pol") //nolint

	// Circuit open with passthrough: input returned unchanged
	fr, err := pc.Filter(context.Background(), "original text", "ctx", "doc", "pol")
	if err != nil {
		t.Fatalf("Expected passthrough, got error: %v", err)
	}
	if fr.FilteredText != "original text" {
		t.Errorf("Expected original text returned unchanged, got %s", fr.FilteredText)
	}
}

func TestProxy_CircuitBreakerOpen_Returns503(t *testing.T) {
	// Philter always fails
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer philterSrv.Close()

	cfg := testConfig(philterSrv.URL)
	pc := newPhilterClient(http.DefaultClient, philterSrv.URL,
		RetryConfig{MaxAttempts: 1, InitialBackoffMs: 1, MaxBackoffMs: 10},
		CircuitBreakerConfig{Enabled: true, Threshold: 1, TimeoutSeconds: 30, Fallback: "block"},
	)
	// Trigger the circuit open
	pc.Filter(context.Background(), "x", "ctx", "doc", "pol") //nolint

	reg := prometheus.NewRegistry()
	proxy := &Proxy{
		config:       cfg,
		philter:      pc,
		metrics:      newMetrics(reg),
		openaiTarget: mustParseURL("http://127.0.0.1:1"),
		openaiClient: http.DefaultClient,
	}

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 when circuit breaker open, got %d", w.Code)
	}
}

// ── OpenAI-compatible providers ───────────────────────────────────────────────

func newOpenAICompatProxy(philterURL, providerURL, name string) *Proxy {
	cfg := testConfig(philterURL)
	cfg.Providers.OpenAICompatible = map[string]ProviderConfig{
		name: {Target: providerURL},
	}
	u, _ := url.Parse(providerURL)
	return &Proxy{
		config:                  cfg,
		philter:                 testPhilterClient(philterURL),
		openaiCompatibleTargets: map[string]*url.URL{name: u},
		openaiCompatibleClients: map[string]*http.Client{name: http.DefaultClient},
	}
}

func TestOpenAICompat_BasicRedaction(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
	}))
	defer philterSrv.Close()

	var receivedPath string
	var receivedBody []byte
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`))
	}))
	defer providerSrv.Close()

	proxy := newOpenAICompatProxy(philterSrv.URL, providerSrv.URL, "mistral")

	body := `{"model":"mistral-large","messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}`
	req := httptest.NewRequest("POST", "/mistral/v1/chat/completions", strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// Path prefix stripped before forwarding
	if receivedPath != "/v1/chat/completions" {
		t.Errorf("Expected forwarded path /v1/chat/completions, got %s", receivedPath)
	}
	// Content was redacted
	var forwarded OpenAIRequest
	json.Unmarshal(receivedBody, &forwarded)
	var content string
	json.Unmarshal(forwarded.Messages[0].Content, &content)
	if content != "REDACTED" {
		t.Errorf("Expected content REDACTED, got %q", content)
	}
}

func TestOpenAICompat_AuditProvider(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`))
	}))
	defer providerSrv.Close()

	var buf strings.Builder
	proxy := newOpenAICompatProxy(philterSrv.URL, providerSrv.URL, "cohere")
	proxy.auditLogger = slog.New(slog.NewJSONHandler(&buf, nil))

	req := httptest.NewRequest("POST", "/cohere/v1/chat/completions",
		strings.NewReader(`{"model":"command-r","messages":[{"role":"user","content":"hello"}]}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if !strings.Contains(buf.String(), `"provider":"cohere"`) {
		t.Errorf("Expected provider=cohere in audit log, got: %s", buf.String())
	}
}

func TestOpenAICompat_PhilterError(t *testing.T) {
	proxy := newOpenAICompatProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "mistral")
	req := httptest.NewRequest("POST", "/mistral/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d", w.Code)
	}
}

func TestOpenAICompat_UnknownProviderFallsThrough(t *testing.T) {
	// /unknown/v1/chat/completions — "unknown" not in openaiCompatible — falls
	// through to the default OpenAI handler, which will hit 127.0.0.1:1 and 502.
	proxy := newOpenAICompatProxy("http://127.0.0.1:1", "http://127.0.0.1:1", "mistral")
	proxy.openaiTarget = mustParseURL("http://127.0.0.1:1")
	proxy.openaiClient = http.DefaultClient

	req := httptest.NewRequest("POST", "/unknown/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	// Philter unreachable → 502 (not a 404 — it fell through to the OpenAI handler)
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 (fell through to OpenAI handler), got %d", w.Code)
	}
}

func TestOpenAICompat_RouteMatchingUsesStrippedPath(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the policy applied was the route-matched one, not the default.
		if r.URL.Query().Get("p") != "special-policy" {
			t.Errorf("Expected policy special-policy, got %s", r.URL.Query().Get("p"))
		}
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`))
	}))
	defer providerSrv.Close()

	proxy := newOpenAICompatProxy(philterSrv.URL, providerSrv.URL, "mistral")
	proxy.config.Routes = []RouteConfig{
		{Match: RouteMatch{Path: "/v1/chat/completions"}, Policy: "special-policy"},
	}

	req := httptest.NewRequest("POST", "/mistral/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestResolveOpenAICompatible(t *testing.T) {
	u, _ := url.Parse("https://api.mistral.ai")
	p := &Proxy{
		openaiCompatibleTargets: map[string]*url.URL{"mistral": u},
		openaiCompatibleClients: map[string]*http.Client{"mistral": http.DefaultClient},
	}

	cases := []struct {
		path     string
		name     string
		stripped string
		ok       bool
	}{
		{"/mistral/v1/chat/completions", "mistral", "/v1/chat/completions", true},
		{"/mistral/v1/models", "mistral", "/v1/models", true},
		{"/v1/chat/completions", "", "", false},         // no prefix
		{"/unknown/v1/chat/completions", "", "", false}, // prefix not configured
		{"/mistral", "", "", false},                     // no slash after prefix
		{"/health", "", "", false},
	}
	for _, tc := range cases {
		name, _, _, stripped, ok := p.resolveOpenAICompatible(tc.path)
		if ok != tc.ok || name != tc.name || stripped != tc.stripped {
			t.Errorf("resolveOpenAICompatible(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.path, name, stripped, ok, tc.name, tc.stripped, tc.ok)
		}
	}
}

func TestConfig_OpenAICompatible_Validation(t *testing.T) {
	// Valid
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Providers.OpenAICompatible = map[string]ProviderConfig{
		"mistral": {Target: "https://api.mistral.ai"},
	}
	if err := validateConfig(cfg); err != nil {
		t.Errorf("Expected valid config, got: %v", err)
	}

	// Reserved name
	cfg2 := testConfig("http://127.0.0.1:1")
	cfg2.Providers.OpenAICompatible = map[string]ProviderConfig{
		"v1": {Target: "https://example.com"},
	}
	if err := validateConfig(cfg2); err == nil {
		t.Error("Expected error for reserved name 'v1'")
	}

	// Missing target
	cfg3 := testConfig("http://127.0.0.1:1")
	cfg3.Providers.OpenAICompatible = map[string]ProviderConfig{
		"mistral": {Target: ""},
	}
	if err := validateConfig(cfg3); err == nil {
		t.Error("Expected error for missing target")
	}

	// Empty name
	cfg4 := testConfig("http://127.0.0.1:1")
	cfg4.Providers.OpenAICompatible = map[string]ProviderConfig{
		"": {Target: "https://example.com"},
	}
	if err := validateConfig(cfg4); err == nil {
		t.Error("Expected error for empty name")
	}

	// Invalid target URL
	cfg5 := testConfig("http://127.0.0.1:1")
	cfg5.Providers.OpenAICompatible = map[string]ProviderConfig{
		"mistral": {Target: "://bad-url"},
	}
	if err := validateConfig(cfg5); err == nil {
		t.Error("Expected error for invalid target URL")
	}

	// Name containing a path separator (#192 / security review).
	cfg6 := testConfig("http://127.0.0.1:1")
	cfg6.Providers.OpenAICompatible = map[string]ProviderConfig{
		"foo/bar": {Target: "https://example.com"},
	}
	if err := validateConfig(cfg6); err == nil {
		t.Error("Expected error for a compat name containing '/'")
	}

	// Name colliding with a built-in provider identifier.
	for _, reserved := range []string{"openai", "anthropic", "gemini", "ollama", "bedrock", "azure", "vertex"} {
		cfg := testConfig("http://127.0.0.1:1")
		cfg.Providers.OpenAICompatible = map[string]ProviderConfig{
			reserved: {Target: "https://example.com"},
		}
		if err := validateConfig(cfg); err == nil {
			t.Errorf("Expected error for reserved built-in provider name %q", reserved)
		}
	}
}

// TestOpenAICompat_ScopeEnforced confirms per-key scopes.providers is enforced
// for an openaiCompatible provider: a key scoped to the compat name is allowed,
// and a key scoped to a different provider is denied with scope_denied_provider.
func TestOpenAICompat_ScopeEnforced(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterSrv.Close()
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`))
	}))
	defer providerSrv.Close()
	u, _ := url.Parse(providerSrv.URL)

	newProxy := func(t *testing.T, scopedProvider string) *Proxy {
		entry := APIKeyEntry{Key: "secret", Scopes: &APIKeyScopes{Providers: []string{scopedProvider}}}
		ks, err := newKeyStore([]APIKeyEntry{entry})
		if err != nil {
			t.Fatalf("newKeyStore: %v", err)
		}
		cfg := testConfig(philterSrv.URL)
		cfg.Auth.APIKeys = []APIKeyEntry{entry}
		return &Proxy{
			config:                  cfg,
			philter:                 testPhilterClient(philterSrv.URL),
			keyStore:                ks,
			openaiCompatibleTargets: map[string]*url.URL{"mistral": u},
			openaiCompatibleClients: map[string]*http.Client{"mistral": http.DefaultClient},
		}
	}

	body := `{"model":"mistral-large","messages":[{"role":"user","content":"hi"}]}`

	// Key scoped to the compat provider -> allowed.
	allow := newProxy(t, "mistral")
	req := httptest.NewRequest("POST", "/mistral/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("x-philter-proxy-key", "secret")
	w := httptest.NewRecorder()
	allow.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("key scoped to mistral should be allowed, got %d: %s", w.Code, w.Body.String())
	}

	// Key scoped to a different provider -> denied.
	deny := newProxy(t, "openai")
	req = httptest.NewRequest("POST", "/mistral/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("x-philter-proxy-key", "secret")
	w = httptest.NewRecorder()
	deny.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("key scoped to openai should be denied for a mistral request, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "scope_denied_provider") {
		t.Errorf("expected scope_denied_provider, got: %s", w.Body.String())
	}
}

func TestOpenAICompat_MultipleProviders(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterSrv.Close()

	var mistralHits, cohereHits int
	mistralSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mistralHits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"mistral"}}]}`))
	}))
	defer mistralSrv.Close()
	cohereSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cohereHits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"cohere"}}]}`))
	}))
	defer cohereSrv.Close()

	cfg := testConfig(philterSrv.URL)
	mistralURL, _ := url.Parse(mistralSrv.URL)
	cohereURL, _ := url.Parse(cohereSrv.URL)
	proxy := &Proxy{
		config:  cfg,
		philter: testPhilterClient(philterSrv.URL),
		openaiCompatibleTargets: map[string]*url.URL{
			"mistral": mistralURL,
			"cohere":  cohereURL,
		},
		openaiCompatibleClients: map[string]*http.Client{
			"mistral": http.DefaultClient,
			"cohere":  http.DefaultClient,
		},
	}

	body := `{"model":"m","messages":[{"role":"user","content":"hello"}]}`

	req1 := httptest.NewRequest("POST", "/mistral/v1/chat/completions", strings.NewReader(body))
	proxy.ServeHTTP(httptest.NewRecorder(), req1)

	req2 := httptest.NewRequest("POST", "/cohere/v1/chat/completions", strings.NewReader(body))
	proxy.ServeHTTP(httptest.NewRecorder(), req2)

	req3 := httptest.NewRequest("POST", "/mistral/v1/chat/completions", strings.NewReader(body))
	proxy.ServeHTTP(httptest.NewRecorder(), req3)

	if mistralHits != 2 {
		t.Errorf("Expected 2 requests to mistral, got %d", mistralHits)
	}
	if cohereHits != 1 {
		t.Errorf("Expected 1 request to cohere, got %d", cohereHits)
	}
}

// ── Bedrock Converse API ──────────────────────────────────────────────────────

// staticCreds returns a CredentialsProvider that always returns the supplied values.
func staticCreds(key, secret string) *testCredProvider {
	return &testCredProvider{key: key, secret: secret}
}

type testCredProvider struct{ key, secret string }

func (tc *testCredProvider) Retrieve(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: tc.key, SecretAccessKey: tc.secret, Source: "test"}, nil
}

// newBedrockProxy builds a proxy with a fake Bedrock endpoint and fake AWS creds.
func newBedrockProxy(philterURL, bedrockURL string) *Proxy {
	cfg := testConfig(philterURL)
	// Parse just the host+scheme for the bedrockTarget; the handler builds the URL itself.
	u, _ := url.Parse(bedrockURL)
	_ = u
	return &Proxy{
		config:        cfg,
		philter:       testPhilterClient(philterURL),
		bedrockRegion: "us-east-1",
		bedrockCreds:  staticCreds("AKIATEST", "secrettest"),
		bedrockClient: &http.Client{Transport: &mockBedrockTransport{bedrockURL: bedrockURL}},
	}
}

// mockBedrockTransport rewrites the request Host to point at the test server,
// bypassing the actual AWS endpoint derived from the region.
type mockBedrockTransport struct{ bedrockURL string }

func (m *mockBedrockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(m.bedrockURL)
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	return http.DefaultTransport.RoundTrip(req)
}

func TestBedrock_BasicRedaction(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
	}))
	defer philterSrv.Close()

	var receivedBody []byte
	bedrockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BedrockConverseResponse{
			Output: BedrockConverseOutput{
				Message: BedrockMessage{
					Role:    "assistant",
					Content: []BedrockContentBlock{{Text: "Hello"}},
				},
			},
			StopReason: "end_turn",
		})
	}))
	defer bedrockSrv.Close()

	proxy := newBedrockProxy(philterSrv.URL, bedrockSrv.URL)

	body := `{"messages":[{"role":"user","content":[{"text":"John Smith"}]}]}`
	req := httptest.NewRequest("POST", "/model/amazon.titan-text-v1/converse", strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var forwarded BedrockConverseRequest
	if err := json.Unmarshal(receivedBody, &forwarded); err != nil {
		t.Fatalf("Could not parse forwarded body: %v", err)
	}
	if len(forwarded.Messages) == 0 || len(forwarded.Messages[0].Content) == 0 {
		t.Fatal("Expected forwarded message content")
	}
	if forwarded.Messages[0].Content[0].Text != "REDACTED" {
		t.Errorf("Expected content redacted, got %q", forwarded.Messages[0].Content[0].Text)
	}
}

func TestBedrock_SystemPromptRedaction(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterSrv.Close()

	var receivedBody []byte
	bedrockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BedrockConverseResponse{
			Output: BedrockConverseOutput{
				Message: BedrockMessage{Role: "assistant", Content: []BedrockContentBlock{{Text: "OK"}}},
			},
		})
	}))
	defer bedrockSrv.Close()

	proxy := newBedrockProxy(philterSrv.URL, bedrockSrv.URL)

	body := `{"messages":[{"role":"user","content":[{"text":"hello"}]}],"system":[{"text":"Patient SSN: 123-45-6789"}]}`
	req := httptest.NewRequest("POST", "/model/anthropic.claude-3-sonnet/converse", strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var forwarded BedrockConverseRequest
	json.Unmarshal(receivedBody, &forwarded)
	if len(forwarded.System) == 0 || forwarded.System[0].Text != "REDACTED" {
		t.Errorf("Expected system prompt redacted, got %+v", forwarded.System)
	}
}

func TestBedrock_PhilterError(t *testing.T) {
	proxy := newBedrockProxy("http://127.0.0.1:1", "http://127.0.0.1:1")

	body := `{"messages":[{"role":"user","content":[{"text":"hello"}]}]}`
	req := httptest.NewRequest("POST", "/model/amazon.titan-text-v1/converse", strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 when Philter unreachable, got %d", w.Code)
	}
}

func TestBedrock_BadJSON(t *testing.T) {
	philterSrv := philterOK()
	defer philterSrv.Close()

	proxy := newBedrockProxy(philterSrv.URL, "http://127.0.0.1:1")
	req := httptest.NewRequest("POST", "/model/amazon.titan-text-v1/converse", strings.NewReader("{bad}"))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestBedrock_NotConfigured(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	proxy := &Proxy{
		config:  cfg,
		philter: testPhilterClient("http://127.0.0.1:1"),
		// bedrockRegion intentionally empty
	}

	req := httptest.NewRequest("POST", "/model/amazon.titan-text-v1/converse", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 when Bedrock not configured, got %d", w.Code)
	}
}

func TestBedrock_ModelFromPath(t *testing.T) {
	cases := []struct {
		path  string
		model string
	}{
		{"/model/amazon.titan-text-v1/converse", "amazon.titan-text-v1"},
		{"/model/anthropic.claude-3-sonnet-20240229-v1:0/converse", "anthropic.claude-3-sonnet-20240229-v1:0"},
		{"/model/meta.llama3-8b-instruct-v1:0/converse", "meta.llama3-8b-instruct-v1:0"},
	}
	for _, tc := range cases {
		got := bedrockModelFromPath(tc.path)
		if got != tc.model {
			t.Errorf("bedrockModelFromPath(%q) = %q, want %q", tc.path, got, tc.model)
		}
	}
}

func TestBedrock_IsBedrockPath(t *testing.T) {
	yes := []string{
		"/model/amazon.titan-text-v1/converse",
		"/model/anthropic.claude-3/converse",
		"/model/amazon.titan-text-v1/converse-stream",
		"/model/anthropic.claude-3/converse-stream",
	}
	no := []string{
		"/v1/chat/completions",
		"/v1/messages",
		"/api/generate",
		"/model/foo/converseStream",
		"/model/foo",
		"/health",
	}
	for _, p := range yes {
		if !isBedrockPath(p) {
			t.Errorf("Expected isBedrockPath(%q) = true", p)
		}
	}
	for _, p := range no {
		if isBedrockPath(p) {
			t.Errorf("Expected isBedrockPath(%q) = false", p)
		}
	}
}

func TestBedrock_AuditLog(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
	}))
	defer philterSrv.Close()

	bedrockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BedrockConverseResponse{
			Output: BedrockConverseOutput{
				Message: BedrockMessage{Role: "assistant", Content: []BedrockContentBlock{{Text: "OK"}}},
			},
		})
	}))
	defer bedrockSrv.Close()

	var buf strings.Builder
	auditLogger := slog.New(slog.NewJSONHandler(&buf, nil))

	proxy := newBedrockProxy(philterSrv.URL, bedrockSrv.URL)
	proxy.auditLogger = auditLogger

	body := `{"messages":[{"role":"user","content":[{"text":"hello world"}]}]}`
	req := httptest.NewRequest("POST", "/model/amazon.titan-text-v1/converse", strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	log := buf.String()
	if !strings.Contains(log, `"provider":"bedrock"`) {
		t.Errorf("Expected provider=bedrock in audit log, got: %s", log)
	}
	if !strings.Contains(log, `"model":"amazon.titan-text-v1"`) {
		t.Errorf("Expected model in audit log, got: %s", log)
	}
}

func TestBedrock_RoleArnCredentials(t *testing.T) {
	// mockSTS satisfies stscreds.AssumeRoleAPIClient and returns deterministic fake creds.
	var assumedRoleARN string
	mockSTS := &mockSTSClient{
		fn: func(ctx context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			assumedRoleARN = aws.ToString(in.RoleArn)
			exp := time.Now().Add(time.Hour)
			return &sts.AssumeRoleOutput{
				Credentials: &stypes.Credentials{
					AccessKeyId:     aws.String("ASIAMOCK"),
					SecretAccessKey: aws.String("mocksecret"),
					SessionToken:    aws.String("mocktoken"),
					Expiration:      &exp,
				},
			}, nil
		},
	}

	roleArn := "arn:aws:iam::123456789012:role/BedrockRole"
	creds := aws.NewCredentialsCache(
		stscreds.NewAssumeRoleProvider(mockSTS, roleArn),
	)

	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterSrv.Close()

	bedrockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BedrockConverseResponse{
			Output: BedrockConverseOutput{
				Message: BedrockMessage{Role: "assistant", Content: []BedrockContentBlock{{Text: "OK"}}},
			},
		})
	}))
	defer bedrockSrv.Close()

	cfg := testConfig(philterSrv.URL)
	proxy := &Proxy{
		config:        cfg,
		philter:       testPhilterClient(philterSrv.URL),
		bedrockRegion: "us-east-1",
		bedrockCreds:  creds,
		bedrockClient: &http.Client{Transport: &mockBedrockTransport{bedrockURL: bedrockSrv.URL}},
	}

	body := `{"messages":[{"role":"user","content":[{"text":"hello"}]}]}`
	req := httptest.NewRequest("POST", "/model/amazon.titan-text-v1/converse", strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if assumedRoleARN != roleArn {
		t.Errorf("Expected STS AssumeRole called with %q, got %q", roleArn, assumedRoleARN)
	}
}

type mockSTSClient struct {
	fn func(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

func (m *mockSTSClient) AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, opts ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	return m.fn(ctx, in, opts...)
}

func TestBedrock_OutboundScan_Redact(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", []Span{{FilterType: "NER_ENTITY"}}))
	}))
	defer philterSrv.Close()

	bedrockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BedrockConverseResponse{
			Output: BedrockConverseOutput{
				Message: BedrockMessage{
					Role:    "assistant",
					Content: []BedrockContentBlock{{Text: "John Smith"}},
				},
			},
		})
	}))
	defer bedrockSrv.Close()

	proxy := newBedrockProxy(philterSrv.URL, bedrockSrv.URL)
	proxy.config.Defaults.Outbound = OutboundConfig{Enabled: true, Action: "redact"}

	body := `{"messages":[{"role":"user","content":[{"text":"hello"}]}]}`
	req := httptest.NewRequest("POST", "/model/amazon.titan-text-v1/converse", strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var resp BedrockConverseResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if len(resp.Output.Message.Content) == 0 || resp.Output.Message.Content[0].Text != "REDACTED" {
		t.Errorf("Expected outbound response content to be REDACTED, got %+v", resp.Output.Message.Content)
	}
}

// ── Token usage tracking ──────────────────────────────────────────────────────

func TestExtractTokenUsage_OpenAI(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	p, c := extractTokenUsage("openai", body)
	if p != 10 || c != 5 {
		t.Errorf("Expected (10,5), got (%d,%d)", p, c)
	}
}

func TestExtractTokenUsage_Anthropic(t *testing.T) {
	body := []byte(`{"content":[{"type":"text","text":"hello"}],"usage":{"input_tokens":20,"output_tokens":8}}`)
	p, c := extractTokenUsage("anthropic", body)
	if p != 20 || c != 8 {
		t.Errorf("Expected (20,8), got (%d,%d)", p, c)
	}
}

func TestExtractTokenUsage_Gemini(t *testing.T) {
	body := []byte(`{"candidates":[{"content":{"parts":[{"text":"hi"}]}}],"usageMetadata":{"promptTokenCount":15,"candidatesTokenCount":3,"totalTokenCount":18}}`)
	p, c := extractTokenUsage("gemini", body)
	if p != 15 || c != 3 {
		t.Errorf("Expected (15,3), got (%d,%d)", p, c)
	}
}

func TestExtractTokenUsage_Ollama(t *testing.T) {
	body := []byte(`{"model":"llama3","response":"hi","prompt_eval_count":12,"eval_count":7}`)
	p, c := extractTokenUsage("ollama", body)
	if p != 12 || c != 7 {
		t.Errorf("Expected (12,7), got (%d,%d)", p, c)
	}
}

func TestExtractTokenUsage_Bedrock(t *testing.T) {
	body := []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"hi"}]}},"usage":{"inputTokens":9,"outputTokens":4,"totalTokens":13}}`)
	p, c := extractTokenUsage("bedrock", body)
	if p != 9 || c != 4 {
		t.Errorf("Expected (9,4), got (%d,%d)", p, c)
	}
}

func TestExtractTokenUsage_MissingUsage(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`)
	p, c := extractTokenUsage("openai", body)
	if p != 0 || c != 0 {
		t.Errorf("Expected (0,0) for missing usage, got (%d,%d)", p, c)
	}
}

func TestExtractTokenUsage_InvalidJSON(t *testing.T) {
	p, c := extractTokenUsage("openai", []byte(`not json`))
	if p != 0 || c != 0 {
		t.Errorf("Expected (0,0) for invalid JSON, got (%d,%d)", p, c)
	}
}

func TestTokenUsage_PopulatedInAudit_OpenAI(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	}))
	defer providerSrv.Close()

	cfg := testConfig(philterSrv.URL)
	provURL, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: provURL,
		openaiClient: http.DefaultClient,
	}

	var buf strings.Builder
	proxy.auditLogger = slog.New(slog.NewJSONHandler(&buf, nil))

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	log := buf.String()
	if !strings.Contains(log, `"prompt_tokens":10`) {
		t.Errorf("Expected prompt_tokens=10 in audit log, got: %s", log)
	}
	if !strings.Contains(log, `"completion_tokens":5`) {
		t.Errorf("Expected completion_tokens=5 in audit log, got: %s", log)
	}
}

func TestTokenUsage_PopulatedInAudit_Anthropic(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"hello"}],"usage":{"input_tokens":20,"output_tokens":8}}`))
	}))
	defer providerSrv.Close()

	cfg := testConfig(philterSrv.URL)
	provURL, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config:          cfg,
		philter:         testPhilterClient(philterSrv.URL),
		anthropicTarget: provURL,
		anthropicClient: http.DefaultClient,
	}

	var buf strings.Builder
	proxy.auditLogger = slog.New(slog.NewJSONHandler(&buf, nil))

	req := httptest.NewRequest("POST", "/v1/messages",
		strings.NewReader(`{"model":"claude-3","max_tokens":100,"messages":[{"role":"user","content":"hello"}]}`))
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	log := buf.String()
	if !strings.Contains(log, `"prompt_tokens":20`) {
		t.Errorf("Expected prompt_tokens=20 in audit log, got: %s", log)
	}
	if !strings.Contains(log, `"completion_tokens":8`) {
		t.Errorf("Expected completion_tokens=8 in audit log, got: %s", log)
	}
}

func TestTokenUsage_PopulatedInAudit_Gemini(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"hello"}]}}],"usageMetadata":{"promptTokenCount":15,"candidatesTokenCount":3,"totalTokenCount":18}}`))
	}))
	defer providerSrv.Close()

	cfg := testConfig(philterSrv.URL)
	provURL, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterSrv.URL),
		geminiTarget: provURL,
		geminiClient: http.DefaultClient,
	}

	var buf strings.Builder
	proxy.auditLogger = slog.New(slog.NewJSONHandler(&buf, nil))

	req := httptest.NewRequest("POST", "/v1beta/models/gemini-2.0-flash:generateContent",
		strings.NewReader(`{"contents":[{"parts":[{"text":"hello"}]}]}`))
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	log := buf.String()
	if !strings.Contains(log, `"prompt_tokens":15`) {
		t.Errorf("Expected prompt_tokens=15 in audit log, got: %s", log)
	}
	if !strings.Contains(log, `"completion_tokens":3`) {
		t.Errorf("Expected completion_tokens=3 in audit log, got: %s", log)
	}
}

func TestTokenUsage_PopulatedInAudit_Ollama(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"model":"llama3","response":"hello","prompt_eval_count":12,"eval_count":7}`))
	}))
	defer providerSrv.Close()

	cfg := testConfig(philterSrv.URL)
	provURL, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterSrv.URL),
		ollamaTarget: provURL,
		ollamaClient: http.DefaultClient,
	}

	var buf strings.Builder
	proxy.auditLogger = slog.New(slog.NewJSONHandler(&buf, nil))

	req := httptest.NewRequest("POST", "/api/generate",
		strings.NewReader(`{"model":"llama3","prompt":"hello","stream":false}`))
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	log := buf.String()
	if !strings.Contains(log, `"prompt_tokens":12`) {
		t.Errorf("Expected prompt_tokens=12 in audit log, got: %s", log)
	}
	if !strings.Contains(log, `"completion_tokens":7`) {
		t.Errorf("Expected completion_tokens=7 in audit log, got: %s", log)
	}
}

func TestTokenUsage_PopulatedInAudit_Bedrock(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	bedrockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"output":{"message":{"role":"assistant","content":[{"text":"hello"}]}},"usage":{"inputTokens":9,"outputTokens":4,"totalTokens":13}}`))
	}))
	defer bedrockSrv.Close()

	proxy := newBedrockProxy(philterSrv.URL, bedrockSrv.URL)

	var buf strings.Builder
	proxy.auditLogger = slog.New(slog.NewJSONHandler(&buf, nil))

	req := httptest.NewRequest("POST", "/model/amazon.titan-text-v1/converse",
		strings.NewReader(`{"messages":[{"role":"user","content":[{"text":"hello"}]}]}`))
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	log := buf.String()
	if !strings.Contains(log, `"prompt_tokens":9`) {
		t.Errorf("Expected prompt_tokens=9 in audit log, got: %s", log)
	}
	if !strings.Contains(log, `"completion_tokens":4`) {
		t.Errorf("Expected completion_tokens=4 in audit log, got: %s", log)
	}
}

func TestTokenUsage_OutboundScanPath(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	}))
	defer providerSrv.Close()

	proxy := newOutboundProxy(philterSrv.URL, providerSrv.URL, "openai", "redact")

	var buf strings.Builder
	proxy.auditLogger = slog.New(slog.NewJSONHandler(&buf, nil))

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	// The inbound audit entry should carry the token counts.
	log := buf.String()
	if !strings.Contains(log, `"prompt_tokens":10`) {
		t.Errorf("Expected prompt_tokens=10 in inbound audit log entry, got: %s", log)
	}
	if !strings.Contains(log, `"completion_tokens":5`) {
		t.Errorf("Expected completion_tokens=5 in inbound audit log entry, got: %s", log)
	}
}

func TestTokenUsage_OpenAICompatPath(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":8,"completion_tokens":3,"total_tokens":11}}`))
	}))
	defer providerSrv.Close()

	proxy := newOpenAICompatProxy(philterSrv.URL, providerSrv.URL, "mistral")

	var buf strings.Builder
	proxy.auditLogger = slog.New(slog.NewJSONHandler(&buf, nil))

	req := httptest.NewRequest("POST", "/mistral/v1/chat/completions",
		strings.NewReader(`{"model":"mistral-large","messages":[{"role":"user","content":"hello"}]}`))
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	log := buf.String()
	if !strings.Contains(log, `"prompt_tokens":8`) {
		t.Errorf("Expected prompt_tokens=8 in audit log, got: %s", log)
	}
	if !strings.Contains(log, `"completion_tokens":3`) {
		t.Errorf("Expected completion_tokens=3 in audit log, got: %s", log)
	}
}

func TestTokenUsage_PrometheusMetrics(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	}))
	defer providerSrv.Close()

	proxy, metrics := newTestProxy(philterSrv.URL, providerSrv.URL, "openai")

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if got := counterVecValue(metrics.promptTokensTotal, "openai", "gpt-4"); got != 10 {
		t.Errorf("Expected promptTokensTotal=10, got %g", got)
	}
	if got := counterVecValue(metrics.completionTokensTotal, "openai", "gpt-4"); got != 5 {
		t.Errorf("Expected completionTokensTotal=5, got %g", got)
	}
}

// ── Authentication ────────────────────────────────────────────────────────────

// newAuthProxy builds a proxy with API key authentication configured.
// keys maps key value → optional policy override ("" = no override).
func newAuthProxy(philterURL, providerURL string, keys map[string]string) *Proxy {
	cfg := testConfig(philterURL)
	u, _ := url.Parse(providerURL)
	return &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterURL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
		keyStore:     testKeyStore(keys),
	}
}

func TestAuth_ValidKey_Passes(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	defer providerSrv.Close()

	proxy := newAuthProxy(philterSrv.URL, providerSrv.URL, map[string]string{"secret-key": ""})

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("x-philter-proxy-key", "secret-key")
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuth_MissingKey_Returns401(t *testing.T) {
	proxy := newAuthProxy("http://127.0.0.1:1", "http://127.0.0.1:1", map[string]string{"secret-key": ""})

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	// No x-philter-proxy-key header
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestAuth_InvalidKey_Returns401(t *testing.T) {
	proxy := newAuthProxy("http://127.0.0.1:1", "http://127.0.0.1:1", map[string]string{"secret-key": ""})

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("x-philter-proxy-key", "wrong-key")
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestAuth_Disabled_WhenNoKeysConfigured(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	defer providerSrv.Close()

	// No keys configured — auth disabled.
	proxy := newAuthProxy(philterSrv.URL, providerSrv.URL, map[string]string{})

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	// No auth header sent — should still succeed.
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 with auth disabled, got %d", w.Code)
	}
}

func TestAuth_KeyBoundPolicy_Override(t *testing.T) {
	var gotPolicy string
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPolicy = r.URL.Query().Get("p")
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	defer providerSrv.Close()

	// Key is bound to "hipaa-safe-harbor"; default policy is "default".
	proxy := newAuthProxy(philterSrv.URL, providerSrv.URL, map[string]string{"hipaa-key": "hipaa-safe-harbor"})

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("x-philter-proxy-key", "hipaa-key")
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if gotPolicy != "hipaa-safe-harbor" {
		t.Errorf("Expected policy hipaa-safe-harbor, got %q", gotPolicy)
	}
}

func TestAuth_HeaderStrippedFromUpstream(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	var receivedKey string
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("x-philter-proxy-key")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	defer providerSrv.Close()

	proxy := newAuthProxy(philterSrv.URL, providerSrv.URL, map[string]string{"secret-key": ""})

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("x-philter-proxy-key", "secret-key")
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if receivedKey != "" {
		t.Errorf("Expected x-philter-proxy-key to be stripped, but provider received %q", receivedKey)
	}
}

func TestAuth_ProviderKeyPassthrough(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()

	var receivedAuth string
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	defer providerSrv.Close()

	proxy := newAuthProxy(philterSrv.URL, providerSrv.URL, map[string]string{"secret-key": ""})

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("x-philter-proxy-key", "secret-key")
	req.Header.Set("Authorization", "Bearer sk-openai-key")
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if receivedAuth != "Bearer sk-openai-key" {
		t.Errorf("Expected Authorization header forwarded unchanged, got %q", receivedAuth)
	}
}

func TestAuth_CustomHeader(t *testing.T) {
	proxy := newAuthProxy("http://127.0.0.1:1", "http://127.0.0.1:1", map[string]string{"secret-key": ""})
	proxy.config.Auth.Header = "x-my-custom-key"

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("x-philter-proxy-key", "secret-key") // wrong header name
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 when key sent in wrong header, got %d", w.Code)
	}
}

func TestConfig_Auth_DuplicateKeys(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Auth.APIKeys = []APIKeyEntry{
		{Key: "key-1"},
		{Key: "key-1"}, // duplicate
	}
	if err := validateConfig(cfg); err == nil {
		t.Error("Expected error for duplicate API key")
	}
}

func TestConfig_Auth_EmptyKey(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Auth.APIKeys = []APIKeyEntry{
		{Key: ""},
	}
	if err := validateConfig(cfg); err == nil {
		t.Error("Expected error for empty API key")
	}
}

func mustKeyStore(entries []APIKeyEntry) *keyStore {
	ks, err := newKeyStore(entries)
	if err != nil {
		panic(err)
	}
	return ks
}

func openAIBody() string {
	return `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
}

// sendRequest drives one request through the proxy and returns the recorder.
func sendRequest(proxy *Proxy, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	return w
}

// Ensure math and atomic imports are used (suppress unused-import errors if
// tests above happen to not reference them directly).
var _ = math.Ceil
var _ atomic.Int64
