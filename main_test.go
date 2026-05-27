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
	"fmt"
	"io/ioutil"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig(philterEndpoint string) *Config {
	cfg := defaultConfig()
	if philterEndpoint != "" {
		cfg.Philter.Endpoint = philterEndpoint
	}
	return cfg
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

	resp := Filter(http.DefaultClient, server.URL, "original text", "context", "docid", "policy")

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
		config:        cfg,
		openaiTarget:  openaiURL,
		openaiClient:  http.DefaultClient,
		philterClient: http.DefaultClient,
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
		config:         testConfig(philterServer.URL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philterClient: http.DefaultClient,
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
		config:         testConfig(philterURL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philterClient: http.DefaultClient,
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
		philterClient:   http.DefaultClient,
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
		philterClient:   http.DefaultClient,
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
		philterClient:   http.DefaultClient,
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
		config:         testConfig(philterURL),
		geminiTarget: geminiURL,
		geminiClient: http.DefaultClient,
		philterClient: http.DefaultClient,
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
	proxy := &Proxy{}
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body, _ := ioutil.ReadAll(w.Body)
	if string(body) != "ok" {
		t.Errorf("Expected body 'ok', got '%s'", string(body))
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
		config:         testConfig(philterURL),
		ollamaTarget: ollamaURL,
		ollamaClient: http.DefaultClient,
		philterClient: http.DefaultClient,
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
		config:         testConfig(philterURL),
		ollamaTarget: ollamaURL,
		ollamaClient: http.DefaultClient,
		philterClient: http.DefaultClient,
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
		config:         testConfig(philterURL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philterClient: http.DefaultClient,
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
		philterClient:   http.DefaultClient,
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
		config:         testConfig(philterURL),
		geminiTarget: geminiURL,
		geminiClient: http.DefaultClient,
		philterClient: http.DefaultClient,
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
		config:         testConfig(philterURL),
		ollamaTarget: ollamaURL,
		ollamaClient: http.DefaultClient,
		philterClient: http.DefaultClient,
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
		w.Header().Set("X-Request-Id", "req-abc")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data: {}\n\n"))
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:         testConfig(philterURL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philterClient: http.DefaultClient,
	}

	reqBody := `{"model": "gpt-4", "messages": [{"role": "user", "content": "secret"}], "stream": true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Header().Get("X-Request-Id") != "req-abc" {
		t.Errorf("Expected X-Request-Id header forwarded, got '%s'", w.Header().Get("X-Request-Id"))
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
		config:         testConfig(philterURL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philterClient: http.DefaultClient,
		auditLogger:    auditLogger,
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
		config:         testConfig(philterURL),
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philterClient: http.DefaultClient,
		auditLogger:    nil,
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
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	if ip := clientIP(r); ip != "10.0.0.1" {
		t.Errorf("Expected '10.0.0.1', got '%s'", ip)
	}

	r.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	if ip := clientIP(r); ip != "203.0.113.50" {
		t.Errorf("Expected '203.0.113.50', got '%s'", ip)
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
		config:        testConfig(philterServer.URL),
		openaiTarget:  openaiURL,
		openaiClient:  http.DefaultClient,
		philterClient: http.DefaultClient,
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
		config:        testConfig(philterServer.URL),
		openaiTarget:  openaiURL,
		openaiClient:  http.DefaultClient,
		philterClient: http.DefaultClient,
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
		config:        testConfig(philterServer.URL),
		openaiTarget:  openaiURL,
		openaiClient:  http.DefaultClient,
		philterClient: http.DefaultClient,
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
		philterClient:   http.DefaultClient,
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
		config:        testConfig(philterServer.URL),
		geminiTarget:  geminiURL,
		geminiClient:  http.DefaultClient,
		philterClient: http.DefaultClient,
	}

	reqBody := `{"contents":[{"parts":[{"functionResponse":{"name":"get_patient","response":{"result":"Patient John Smith, SSN 123-45-6789"}}}]}]}`
	req := httptest.NewRequest("POST", "/v1beta/models/gemini-pro:generateContent", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}
